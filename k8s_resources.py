import base64
import logging
import os
import tempfile
import json
from contextlib import contextmanager
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from eks_token import get_token

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


@contextmanager
def _get_api_clients_from_kubeconfig_content(kubeconfig_content):
    """Creates Kubernetes API clients from kubeconfig content."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as kubeconfig_file:
        kubeconfig_file.write(kubeconfig_content)
        kubeconfig_path = kubeconfig_file.name
    try:
        api_client = config.new_client_from_config(config_file=kubeconfig_path)
        yield (
            client.CoreV1Api(api_client),
            client.AppsV1Api(api_client),
            client.BatchV1Api(api_client),
            client.NetworkingV1Api(api_client),
            client.AutoscalingV2Api(api_client),
            client.RbacAuthorizationV1Api(api_client),
            client.PolicyV1Api(api_client),
        )
    finally:
        if os.path.exists(kubeconfig_path):
            os.remove(kubeconfig_path)


@contextmanager
def _get_api_clients_for_eks(cluster_details):
    """Creates Kubernetes API clients for an EKS cluster."""
    cluster_name = cluster_details["name"]
    endpoint = cluster_details["endpoint"]
    ca_data = cluster_details["certificateAuthority"]["data"]
    region = cluster_details["region"]

    logging.info("  - Generating EKS token for cluster '%s'", cluster_name)
    token = get_token(cluster_name=cluster_name)["status"]["token"]

    configuration = client.Configuration()
    configuration.host = endpoint
    configuration.api_key["authorization"] = token
    configuration.api_key_prefix["authorization"] = "Bearer"

    ca_cert_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as ca_cert:
            ca_cert.write(base64.b64decode(ca_data).decode("utf-8"))
            ca_cert_path = ca_cert.name
        configuration.ssl_ca_cert = ca_cert_path
        api_client = client.ApiClient(configuration)
        yield (
            client.CoreV1Api(api_client),
            client.AppsV1Api(api_client),
            client.BatchV1Api(api_client),
            client.NetworkingV1Api(api_client),
            client.AutoscalingV2Api(api_client),
            client.RbacAuthorizationV1Api(api_client),
            client.PolicyV1Api(api_client),
        )
    finally:
        if ca_cert_path and os.path.exists(ca_cert_path):
            os.remove(ca_cert_path)


def get_node_details(api_client):
    nodes = []
    try:
        response = api_client.list_node()
        for node in response.items:
            nodes.append({
                'name': node.metadata.name,
                'status': node.status.conditions[-1].type if node.status.conditions else 'Unknown',
                'instance_type': node.metadata.labels.get('beta.kubernetes.io/instance-type', 'N/A'),
                'zone': node.metadata.labels.get('topology.kubernetes.io/zone', 'N/A'),
                'os_image': node.status.node_info.os_image,
                'kernel_version': node.status.node_info.kernel_version,
                'kubelet_version': node.status.node_info.kubelet_version,
                'allocatable_cpu': node.status.allocatable.get('cpu', '0'),
                'allocatable_memory': node.status.allocatable.get('memory', '0'),
            })
    except ApiException as e:
        logging.error("Error fetching nodes: %s", e)
    return nodes

def get_pod_details(api_client):
    pods = []
    try:
        response = api_client.list_pod_for_all_namespaces()
        for pod in response.items:
            containers = pod.spec.containers
            container_images = [c.image for c in containers]
            pods.append({
                'namespace': pod.metadata.namespace,
                'name': pod.metadata.name,
                'status': pod.status.phase,
                'pod_ip': pod.status.pod_ip,
                'node_name': pod.spec.node_name,
                'service_account': pod.spec.service_account_name,
                'container_images': ", ".join(container_images),
            })
    except ApiException as e:
        logging.error("Error fetching pods: %s", e)
    return pods

def get_deployment_details(api_client):
    deployments = []
    try:
        response = api_client.list_deployment_for_all_namespaces()
        for deployment in response.items:
            containers = deployment.spec.template.spec.containers
            container_images = [c.image for c in containers]
            deployments.append({
                'namespace': deployment.metadata.namespace,
                'name': deployment.metadata.name,
                'replicas_desired': deployment.spec.replicas,
                'replicas_ready': deployment.status.ready_replicas or 0,
                'strategy': deployment.spec.strategy.type,
                'container_images': ", ".join(container_images),
            })
    except ApiException as e:
        logging.error("Error fetching deployments: %s", e)
    return deployments

def get_service_details(api_client):
    services = []
    try:
        response = api_client.list_service_for_all_namespaces()
        for service in response.items:
            ports = [f"{p.name}:{p.port}/{p.protocol}" for p in service.spec.ports] if service.spec.ports else []
            load_balancer_ip = ''
            if service.status.load_balancer and service.status.load_balancer.ingress:
                load_balancer_ip = service.status.load_balancer.ingress[0].ip
            
            services.append({
                'namespace': service.metadata.namespace,
                'name': service.metadata.name,
                'type': service.spec.type,
                'cluster_ip': service.spec.cluster_ip,
                'external_ip': load_balancer_ip or 'N/A',
                'ports': ", ".join(ports),
                'selector': str(service.spec.selector),
            })
    except ApiException as e:
        logging.error("Error fetching services: %s", e)
    return services

def get_statefulset_details(api_client):
    statefulsets = []
    try:
        response = api_client.list_stateful_set_for_all_namespaces()
        for ss in response.items:
            containers = ss.spec.template.spec.containers
            container_images = [c.image for c in containers]
            statefulsets.append({
                'namespace': ss.metadata.namespace,
                'name': ss.metadata.name,
                'replicas_desired': ss.spec.replicas,
                'replicas_ready': ss.status.ready_replicas or 0,
                'service_name': ss.spec.service_name,
                'container_images': ", ".join(container_images),
            })
    except ApiException as e:
        logging.error("Error fetching statefulsets: %s", e)
    return statefulsets

def get_daemonset_details(api_client):
    daemonsets = []
    try:
        response = api_client.list_daemon_set_for_all_namespaces()
        for ds in response.items:
            containers = ds.spec.template.spec.containers
            container_images = [c.image for c in containers]
            daemonsets.append({
                'namespace': ds.metadata.namespace,
                'name': ds.metadata.name,
                'desired_scheduled': ds.status.desired_number_scheduled,
                'current_scheduled': ds.status.current_number_scheduled,
                'ready': ds.status.number_ready,
                'container_images': ", ".join(container_images),
            })
    except ApiException as e:
        logging.error("Error fetching daemonsets: %s", e)
    return daemonsets

def get_job_details(api_client):
    jobs = []
    try:
        response = api_client.list_job_for_all_namespaces()
        for job in response.items:
            jobs.append({
                'namespace': job.metadata.namespace,
                'name': job.metadata.name,
                'completions': job.spec.completions,
                'succeeded': job.status.succeeded or 0,
                'failed': job.status.failed or 0,
                'start_time': job.status.start_time,
            })
    except ApiException as e:
        logging.error("Error fetching jobs: %s", e)
    return jobs

def get_cronjob_details(api_client):
    cronjobs = []
    try:
        response = api_client.list_cron_job_for_all_namespaces()
        for cj in response.items:
            cronjobs.append({
                'namespace': cj.metadata.namespace,
                'name': cj.metadata.name,
                'schedule': cj.spec.schedule,
                'suspend': cj.spec.suspend,
                'last_schedule_time': cj.status.last_schedule_time,
                'active_jobs': len(cj.status.active) if cj.status.active else 0,
            })
    except ApiException as e:
        logging.error("Error fetching cronjobs: %s", e)
    return cronjobs

def get_pv_details(api_client):
    pvs = []
    try:
        response = api_client.list_persistent_volume()
        for pv in response.items:
            pvs.append({
                'name': pv.metadata.name,
                'capacity': pv.spec.capacity.get('storage', 'N/A'),
                'access_modes': ", ".join(pv.spec.access_modes) if pv.spec.access_modes else "",
                'reclaim_policy': pv.spec.persistent_volume_reclaim_policy,
                'status': pv.status.phase,
                'storage_class': pv.spec.storage_class_name,
                'claim_namespace': pv.spec.claim_ref.namespace if pv.spec.claim_ref else 'N/A',
                'claim_name': pv.spec.claim_ref.name if pv.spec.claim_ref else 'N/A',
            })
    except ApiException as e:
        logging.error("Error fetching persistent volumes: %s", e)
    return pvs

def get_namespace_details(api_client):
    """Fetches details for all Namespace objects."""
    namespaces = []
    try:
        response = api_client.list_namespace()
        for ns in response.items:
            namespaces.append({
                'name': ns.metadata.name,
                'status': ns.status.phase,
                'creation_timestamp': ns.metadata.creation_timestamp,
            })
    except ApiException as e:
        logging.error("Error fetching namespaces: %s", e)
    return namespaces

def get_secret_details(api_client):
    """Fetches metadata for all Secret objects."""
    secrets = []
    try:
        response = api_client.list_secret_for_all_namespaces()
        for secret in response.items:
            secrets.append({
                'namespace': secret.metadata.namespace,
                'name': secret.metadata.name,
                'type': secret.type,
                'data_keys': ", ".join(secret.data.keys()) if secret.data else "",
            })
    except ApiException as e:
        logging.error("Error fetching secrets: %s", e)
    return secrets

def get_configmap_details(api_client):
    """Fetches metadata for all ConfigMap objects."""
    configmaps = []
    try:
        response = api_client.list_config_map_for_all_namespaces()
        for cm in response.items:
            data_keys = ", ".join(cm.data.keys()) if cm.data else ""
            configmaps.append({
                'namespace': cm.metadata.namespace,
                'name': cm.metadata.name,
                'data_keys': data_keys,
            })
    except ApiException as e:
        logging.error("Error fetching configmaps: %s", e)
    return configmaps

def get_pvc_details(api_client):
    """Fetches details for all PersistentVolumeClaim objects."""
    pvcs = []
    try:
        response = api_client.list_persistent_volume_claim_for_all_namespaces()
        for pvc in response.items:
            pvcs.append({
                'namespace': pvc.metadata.namespace,
                'name': pvc.metadata.name,
                'status': pvc.status.phase,
                'capacity_request': pvc.spec.resources.requests.get('storage', 'N/A') if pvc.spec.resources.requests else 'N/A',
                'access_modes': ", ".join(pvc.spec.access_modes) if pvc.spec.access_modes else "",
                'storage_class': pvc.spec.storage_class_name,
                'volume_name': pvc.spec.volume_name,
                'volume_mode': pvc.spec.volume_mode,
            })
    except ApiException as e:
        logging.error("Error fetching PVCs: %s", e)
    return pvcs

def get_ingress_details(api_client):
    """Fetches details for all Ingress objects."""
    ingresses = []
    try:
        response = api_client.list_ingress_for_all_namespaces()
        for ingress in response.items:
            hosts = [rule.host for rule in ingress.spec.rules] if ingress.spec.rules else []
            tls_secrets = [tls.secret_name for tls in ingress.spec.tls if tls.secret_name] if ingress.spec.tls else []
            annotations = json.dumps(ingress.metadata.annotations) if ingress.metadata.annotations else '{}'
            load_balancer_ips = [i.ip for i in ingress.status.load_balancer.ingress] if ingress.status.load_balancer.ingress else []
            ingresses.append({
                'namespace': ingress.metadata.namespace,
                'name': ingress.metadata.name,
                'class': ingress.spec.ingress_class_name or 'N/A',
                'hosts': ", ".join(hosts),
                'load_balancer_ips': ", ".join(load_balancer_ips),
                'tls_secret': ", ".join(tls_secrets),
                'annotations': annotations,
            })
    except ApiException as e:
        logging.error("Error fetching ingresses: %s", e)
    return ingresses

def get_networkpolicy_details(api_client):
    """Fetches details for all NetworkPolicy objects."""
    netpols = []
    api_client_instance = client.ApiClient()
    try:
        response = api_client.list_network_policy_for_all_namespaces()
        for np in response.items:
            ingress_rules = json.dumps(api_client_instance.sanitize_for_serialization(np.spec.ingress)) if np.spec.ingress else '[]'
            egress_rules = json.dumps(api_client_instance.sanitize_for_serialization(np.spec.egress)) if np.spec.egress else '[]'
            netpols.append({
                'namespace': np.metadata.namespace,
                'name': np.metadata.name,
                'pod_selector': str(np.spec.pod_selector.match_labels) if np.spec.pod_selector else '{}',
                'policy_types': ", ".join(np.spec.policy_types) if np.spec.policy_types else "",
                'ingress_rules': ingress_rules,
                'egress_rules': egress_rules,
            })
    except ApiException as e:
        logging.error("Error fetching network policies: %s", e)
    return netpols

def get_hpa_details(api_client):
    """Fetches details for all HorizontalPodAutoscaler objects."""
    hpas = []
    api_client_instance = client.ApiClient()
    try:
        response = api_client.list_horizontal_pod_autoscaler_for_all_namespaces()
        for hpa in response.items:
            metrics = json.dumps(api_client_instance.sanitize_for_serialization(hpa.spec.metrics)) if hpa.spec.metrics else '[]'
            hpas.append({
                'namespace': hpa.metadata.namespace,
                'name': hpa.metadata.name,
                'scale_target_ref': f"{hpa.spec.scale_target_ref.kind}/{hpa.spec.scale_target_ref.name}",
                'min_replicas': hpa.spec.min_replicas,
                'max_replicas': hpa.spec.max_replicas,
                'current_replicas': hpa.status.current_replicas,
                'desired_replicas': hpa.status.desired_replicas,
                'metrics': metrics,
            })
    except ApiException as e:
        logging.error("Error fetching HPAs: %s", e)
    return hpas

def get_role_details(api_client):
    """Fetches details for all Role objects."""
    roles = []
    try:
        response = api_client.list_role_for_all_namespaces()
        for role in response.items:
            rules_summary = [f"[{','.join(rule.api_groups)}][{','.join(rule.resources)}][{','.join(rule.verbs)}]" for rule in role.rules] if role.rules else []
            annotations = json.dumps(role.metadata.annotations) if role.metadata.annotations else '{}'
            roles.append({
                'namespace': role.metadata.namespace,
                'name': role.metadata.name,
                'rules': " | ".join(rules_summary),
                'annotations': annotations,
            })
    except ApiException as e:
        logging.error("Error fetching roles: %s", e)
    return roles

def get_rolebinding_details(api_client):
    """Fetches details for all RoleBinding objects."""
    bindings = []
    try:
        response = api_client.list_role_binding_for_all_namespaces()
        for rb in response.items:
            subjects = [f"{s.kind}:{s.name}" for s in rb.subjects] if rb.subjects else []
            bindings.append({
                'namespace': rb.metadata.namespace,
                'name': rb.metadata.name,
                'role_ref': f"{rb.role_ref.kind}/{rb.role_ref.name}",
                'subjects': ", ".join(subjects),
            })
    except ApiException as e:
        logging.error("Error fetching role bindings: %s", e)
    return bindings

def get_resourcequota_details(api_client):
    """Fetches details for all ResourceQuota objects."""
    quotas = []
    try:
        response = api_client.list_resource_quota_for_all_namespaces()
        for quota in response.items:
            quotas.append({
                'namespace': quota.metadata.namespace,
                'name': quota.metadata.name,
                'hard_limits': json.dumps(quota.spec.hard) if quota.spec.hard else '{}',
                'used': json.dumps(quota.status.used) if quota.status.used else '{}',
            })
    except ApiException as e:
        logging.error("Error fetching resource quotas: %s", e)
    return quotas

def get_limitrange_details(api_client):
    """Fetches details for all LimitRange objects."""
    ranges = []
    try:
        response = api_client.list_limit_range_for_all_namespaces()
        for lr in response.items:
            if not lr.spec.limits:
                continue
            for item in lr.spec.limits:
                ranges.append({
                    'name': lr.metadata.name,
                    'namespace': lr.metadata.namespace,
                    'type': item.type,
                    'max_cpu': item.max.get('cpu', 'N/A') if item.max else 'N/A',
                    'max_mem': item.max.get('memory', 'N/A') if item.max else 'N/A',
                    'min_cpu': item.min.get('cpu', 'N/A') if item.min else 'N/A',
                    'min_mem': item.min.get('memory', 'N/A') if item.min else 'N/A',
                    'default_cpu': item.default.get('cpu', 'N/A') if item.default else 'N/A',
                    'default_mem': item.default.get('memory', 'N/A') if item.default else 'N/A',
                    'default_request_cpu': item.default_request.get('cpu', 'N/A') if item.default_request else 'N/A',
                    'default_request_mem': item.default_request.get('memory', 'N/A') if item.default_request else 'N/A',
                })
    except ApiException as e:
        logging.error("Error fetching limit ranges: %s", e)
    return ranges

def get_pdb_details(policy_v1_api, core_v1_api):
    """
    Fetches details for all PodDisruptionBudget objects.
    It attempts a cluster-wide query first and falls back to per-namespace
    queries if the cluster-wide call is denied due to permissions.
    """
    pdbs = []
    items = []
    try:
        # First, try the more efficient cluster-wide call
        items = policy_v1_api.list_pod_disruption_budget_for_all_namespaces().items
    except ApiException as e:
        if e.status not in [401, 403]:
            logging.error("Error fetching PDBs: %s", e)
            return []

        # If unauthorized, fall back to listing PDBs in each namespace individually.
        logging.warning(
            "Could not list PDBs cluster-wide (reason: %s). "
            "Falling back to per-namespace requests. "
            "This may be slower and some resources may be missed if namespace access is restricted.",
            e.reason,
        )
        try:
            namespaces = core_v1_api.list_namespace().items
        except ApiException as ns_list_e:
            logging.error(
                "Could not list namespaces to fall back for PDBs: %s", ns_list_e
            )
            return []

        for ns in namespaces:
            try:
                namespace_pdbs = policy_v1_api.list_namespaced_pod_disruption_budget(
                    ns.metadata.name
                )
                items.extend(namespace_pdbs.items)
            except ApiException as ns_e:
                if ns_e.status in [401, 403]:
                    logging.warning(
                        "Cannot list PDBs in namespace '%s': %s",
                        ns.metadata.name,
                        ns_e.reason,
                    )
                else:
                    logging.error(
                        "Error fetching PDBs in namespace '%s': %s",
                        ns.metadata.name,
                        ns_e,
                    )

    for pdb in items:
        pdbs.append(
            {
                "namespace": pdb.metadata.namespace,
                "name": pdb.metadata.name,
                "min_available": pdb.spec.min_available,
                "max_unavailable": pdb.spec.max_unavailable,
                "selector": str(pdb.spec.selector.match_labels)
                if pdb.spec.selector
                else "{}",
                "current_healthy": pdb.status.current_healthy,
                "desired_healthy": pdb.status.desired_healthy,
            }
        )
    return pdbs

def get_kubernetes_resources(core_v1, apps_v1, batch_v1, networking_v1, autoscaling_v2, rbac_v1, policy_v1):
    """Fetches various resources from a Kubernetes cluster."""
    logging.info("  - Fetching Kubernetes resource details...")
    all_resources = {
        "nodes": get_node_details(core_v1),
        "pods": get_pod_details(core_v1),
        "deployments": get_deployment_details(apps_v1),
        "services": get_service_details(core_v1),
        "statefulsets": get_statefulset_details(apps_v1),
        "daemonsets": get_daemonset_details(apps_v1),
        "jobs": get_job_details(batch_v1),
        "cronjobs": get_cronjob_details(batch_v1),
        "persistent_volumes": get_pv_details(core_v1),
        "namespaces": get_namespace_details(core_v1),
        "secrets": get_secret_details(core_v1),
        "configmaps": get_configmap_details(core_v1),
        "persistent_volume_claims": get_pvc_details(core_v1),
        "ingresses": get_ingress_details(networking_v1),
        "network_policies": get_networkpolicy_details(networking_v1),
        "hpas": get_hpa_details(autoscaling_v2),
        "roles": get_role_details(rbac_v1),
        "role_bindings": get_rolebinding_details(rbac_v1),
        "resource_quotas": get_resourcequota_details(core_v1),
        "limit_ranges": get_limitrange_details(core_v1),
        "pod_disruption_budgets": get_pdb_details(policy_v1, core_v1),
    }
    return all_resources

def get_k8s_details_for_gke():
    """Connects to GKE cluster using local kubeconfig and fetches resources."""
    logging.info("  - Loading kubeconfig for GKE...")
    try:
        config.load_kube_config()
        core_v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        batch_v1 = client.BatchV1Api()
        networking_v1 = client.NetworkingV1Api()
        autoscaling_v2 = client.AutoscalingV2Api()
        rbac_v1 = client.RbacAuthorizationV1Api()
        policy_v1 = client.PolicyV1Api()
        return get_kubernetes_resources(core_v1, apps_v1, batch_v1, networking_v1, autoscaling_v2, rbac_v1, policy_v1)
    except config.ConfigException as e:
        logging.error("  - Could not load kubeconfig for GKE: %s", e)
        return {"error": f"Could not load kubeconfig: {e}"}
    except Exception as e:
        logging.error("  - Could not connect to GKE cluster Kubernetes API: %s", e)
        return {"error": f"Could not connect to Kubernetes API: {e}"}

def get_k8s_details_for_eks(cluster_details):
    """Get Kubernetes details for an EKS cluster."""
    logging.info("  - Getting Kubernetes resource details for EKS cluster '%s'", cluster_details["name"])
    try:
        with _get_api_clients_for_eks(cluster_details) as (core_v1, apps_v1, batch_v1, networking_v1, autoscaling_v2, rbac_v1, policy_v1):
            return get_kubernetes_resources(core_v1, apps_v1, batch_v1, networking_v1, autoscaling_v2, rbac_v1, policy_v1)
    except Exception as e:
        logging.error("  - Could not connect to EKS cluster '%s' Kubernetes API: %s", cluster_details["name"], e)
        return {"error": f"Could not connect to Kubernetes API: {e}"}

def get_k8s_details_for_aks(aks_client, resource_group, cluster_name):
    """Get Kubernetes details for an AKS cluster."""
    logging.info("  - Getting Kubernetes resource details for AKS cluster '%s'", cluster_name)
    try:
        logging.info("  - Fetching admin credentials for AKS cluster '%s'", cluster_name)
        creds = aks_client.managed_clusters.list_cluster_admin_credentials(resource_group, cluster_name).kubeconfigs[0]
        kubeconfig_content: str = creds.value.decode("utf-8")
        with _get_api_clients_from_kubeconfig_content(kubeconfig_content) as (core_v1, apps_v1, batch_v1, networking_v1, autoscaling_v2, rbac_v1, policy_v1):
            return get_kubernetes_resources(core_v1, apps_v1, batch_v1, networking_v1, autoscaling_v2, rbac_v1, policy_v1)
    except Exception as e:
        logging.error("  - Could not connect to AKS cluster '%s' Kubernetes API: %s", cluster_name, e)
        return {"error": f"Could not connect to Kubernetes API: {e}"}
