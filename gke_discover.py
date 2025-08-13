from kubernetes import client, config

def get_node_details(api_client):
    """
    Fetches details for all Node objects in the cluster.
    """
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
                'allocatable_cpu': node.status.allocatable.get('cpu', '0'),
                'allocatable_memory': node.status.allocatable.get('memory', '0'),
            })
    except client.ApiException as e:
        print(f"Error fetching nodes: {e}")
    return nodes

def get_pod_details(api_client):
    """
    Fetches details for all Pod objects across all namespaces.
    """
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
                'node_name': pod.spec.node_name,
                'container_images': ", ".join(container_images),
            })
    except client.ApiException as e:
        print(f"Error fetching pods: {e}")
    return pods

def get_deployment_details(api_client):
    """
    Fetches details for all Deployment objects across all namespaces.
    """
    deployments = []
    try:
        response = api_client.list_deployment_for_all_namespaces()
        for deployment in response.items:
            # Extracting key details from the deployment object
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
    except client.ApiException as e:
        print(f"Error fetching deployments: {e}")
    return deployments

def get_service_details(api_client):
    """
    Fetches details for all Service objects across all namespaces.
    """
    services = []
    try:
        response = api_client.list_service_for_all_namespaces()
        for service in response.items:
            # Extracting key details from the service object
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
    except client.ApiException as e:
        print(f"Error fetching services: {e}")
    return services

def get_statefulset_details(api_client):
    """
    Fetches details for all StatefulSet objects across all namespaces.
    """
    statefulsets = []
    try:
        # Use the appropriate method from the AppsV1Api client
        response = api_client.list_stateful_set_for_all_namespaces()
        for ss in response.items:
            # Extracting key details from the statefulset object
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
    except client.ApiException as e:
        print(f"Error fetching statefulsets: {e}")
    return statefulsets

def get_daemonset_details(api_client):
    """
    Fetches details for all DaemonSet objects across all namespaces.
    """
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
    except client.ApiException as e:
        print(f"Error fetching daemonsets: {e}")
    return daemonsets

def get_job_details(api_client):
    """
    Fetches details for all Job objects across all namespaces.
    """
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
    except client.ApiException as e:
        print(f"Error fetching jobs: {e}")
    return jobs

def get_cronjob_details(api_client):
    """
    Fetches details for all CronJob objects across all namespaces.
    """
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
    except client.ApiException as e:
        print(f"Error fetching cronjobs: {e}")
    return cronjobs

def get_pv_details(api_client):
    """
    Fetches details for all PersistentVolume (PV) objects in the cluster.
    """
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
    except client.ApiException as e:
        print(f"Error fetching persistent volumes: {e}")
    return pvs

def discover_gke_resources():
    """
    Main function to connect to the cluster and fetch all resource details.
    """
    try:
        config.load_kube_config()
    except config.ConfigException:
        print("Could not load kubeconfig. Please ensure you have a valid kubeconfig file.")
        return None

    core_v1 = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()
    batch_v1 = client.BatchV1Api() 
    
    all_resources = {
        "nodes": get_node_details(core_v1),
        "pods": get_pod_details(core_v1),
        "deployments": get_deployment_details(apps_v1),
        "services": get_service_details(core_v1),
        "statefulsets": get_statefulset_details(apps_v1),
        "daemonsets": get_daemonset_details(apps_v1),
        "jobs": get_job_details(batch_v1),
        "cronjobs": get_cronjob_details(batch_v1),
        "pvs": get_pv_details(core_v1),
    }
    
    return all_resources