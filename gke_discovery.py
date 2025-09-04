import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.api_core import exceptions as google_exceptions
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import container_v1, resourcemanager_v3

from k8s_resources import get_k8s_details_for_gke_cluster

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def get_available_projects(credentials):
    """Lists all projects the user has access to."""
    try:
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        logging.info("Searching for accessible Google Cloud projects...")
        # Add a timeout to prevent hanging on environments with many projects or network issues.
        # The API call returns an iterator, so this timeout applies to the initial part of the iteration.
        projects = client.search_projects(timeout=120.0)
        project_ids = [project.project_id for project in projects]
        logging.info("Found %d projects.", len(project_ids))
        return project_ids
    except (DefaultCredentialsError, google_exceptions.PermissionDenied) as e:
        logging.error(
            "Google Cloud authentication failed or you lack permissions to list projects. "
            "Please run 'gcloud auth application-default login' or configure credentials. Error: %s",
            e,
        )
        return []
    except google_exceptions.RetryError as e:
        logging.error(
            "Timeout occurred while searching for Google Cloud projects. "
            "This can happen if you have access to a very large number of projects. "
            "Please specify projects to scan using the --project-id flag. Error: %s",
            e,
        )
        return []
    except Exception as e:
        logging.error("An unexpected error occurred while listing projects: %s", e)
        return []


def get_gke_data_for_project(credentials, project_id):
    """Fetches all GKE cluster data for a given project."""
    logging.info("Scanning GKE clusters in project: %s", project_id)
    clusters_data = []
    try:
        # The parent path is 'projects/{project_id}/locations/-' to list clusters in all locations.
        parent = f"projects/{project_id}/locations/-"
        gke_client = container_v1.ClusterManagerClient(credentials=credentials)

        response = gke_client.list_clusters(parent=parent)

        for cluster_summary in response.clusters:
            logging.info(
                "Found cluster '%s' in project '%s' (location: %s). Getting details...",
                cluster_summary.name,
                project_id,
                cluster_summary.location,
            )

            try:
                # list_clusters can return a partial view. Call get_cluster to ensure we have
                # all details, especially 'masterAuth' which can be missing from the list view.
                cluster_name_path = f"projects/{project_id}/locations/{cluster_summary.location}/clusters/{cluster_summary.name}"
                cluster = gke_client.get_cluster(name=cluster_name_path)
            except Exception as e:
                logging.error(
                    "Failed to get full details for cluster '%s' in project '%s': %s",
                    cluster_summary.name,
                    project_id,
                    e,
                )
                continue

            cluster_details = container_v1.types.Cluster.to_dict(cluster)
            cluster_details["projectId"] = project_id

            # Only attempt to get Kubernetes details if the cluster is in a running state.
            # Other states (PROVISIONING, STOPPING, ERROR) will not have a connectable API endpoint.
            if cluster.status == container_v1.Cluster.Status.RUNNING:
                kubernetes_details = get_k8s_details_for_gke_cluster(
                    cluster_details, credentials
                )
            else:
                logging.warning(
                    "  - Skipping Kubernetes resource discovery for cluster '%s' because its status is '%s'.",
                    cluster.name,
                    cluster.status.name,
                )
                kubernetes_details = {
                    "error": f"Cluster is not in RUNNING state (status: {cluster.status.name})."
                }

            final_cluster_data = {
                "hosting_provider_details": cluster_details,
                "kubernetes_details": kubernetes_details,
            }
            clusters_data.append(final_cluster_data)

        return clusters_data
    except google_exceptions.PermissionDenied as e:
        logging.warning(
            "Could not access GKE in project %s (permission denied). Is the Container Engine API enabled? Skipping. Error: %s",
            project_id,
            e,
        )
        return []
    except google_exceptions.NotFound:
        logging.warning("Project %s not found. Skipping.", project_id)
        return []
    except Exception as e:
        logging.error(
            "An unexpected error occurred while scanning project %s: %s", project_id, e
        )
        return []


def run_gke_discovery(credentials, projects_to_scan):
    """Runs GKE discovery across multiple projects in parallel."""
    all_gke_data = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_project = {
            executor.submit(get_gke_data_for_project, credentials, proj_id): proj_id
            for proj_id in projects_to_scan
        }
        for future in as_completed(future_to_project):
            proj_id = future_to_project[future]
            try:
                data = future.result()
                if data:
                    all_gke_data.extend(data)
            except Exception as exc:
                logging.error("Project %r generated an exception: %s", proj_id, exc)
    return all_gke_data