from azure.identity import DefaultAzureCredential, ChainedTokenCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.resource import SubscriptionClient

def get_aks_clusters(subscription_id: str):
    """
    Fetches AKS cluster data from a specific Azure subscription.
    """
    try:
        credential = DefaultAzureCredential()
        aks_client = ContainerServiceClient(credential, subscription_id)
        clusters_data = []

        for cluster in aks_client.managed_clusters.list():
            clusters_data.append({
                'name': cluster.name,
                'location': cluster.location,
                'resource_group': cluster.resource_group,
                'kubernetes_version': cluster.kubernetes_version,
                'provisioning_state': cluster.provisioning_state,
            })
        return clusters_data

    except ClientAuthenticationError:
        print("Azure authentication failed. Please run 'az login' to authenticate.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def discover_aks_resources(subscription_id: str):
    """
    Discover all AKS clusters in a given subscription.
    """
    if subscription_id:
        return get_aks_clusters(subscription_id)
    else:
        print("No Azure subscription ID specified. Please use the --subscription-id option.")
        return []
