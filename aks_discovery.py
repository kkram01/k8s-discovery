import argparse
import datetime
import json
import logging
import os

# Azure SDK imports
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.core.tools import parse_resource_id
from azure.mgmt.resource import SubscriptionClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_available_subscriptions(credential): # Line 15
    """Lists all subscriptions the user has access to."""
    try:
        subscription_client = SubscriptionClient(credential)
        subscriptions = subscription_client.subscriptions.list()
        return [sub.subscription_id for sub in subscriptions]
    except (ClientAuthenticationError, HttpResponseError) as e:
        logging.error("Azure authentication failed. Please run 'az login' or configure credentials. Error: %s", e)
        return []

def get_aks_data_for_subscription(credential, subscription_id):
    """Fetches all AKS cluster data for a given subscription."""
    logging.info("Scanning AKS clusters in subscription: %s", subscription_id)
    try:
        aks_client = ContainerServiceClient(credential, subscription_id)
        print("Managed Clusters in Subscription: ")
        clusters_data = []

        # The list method gets all clusters in the subscription
        for cluster in aks_client.managed_clusters.list():
            try:
                resource_group = parse_resource_id(cluster.id)['resource_group']
            except KeyError:
                logging.error("Could not parse resource group from cluster ID: %s", cluster.id)
                continue

            # Convert the main cluster object to a dictionary
            cluster_details = cluster.as_dict()

            # Get agent pools (nodepools) for the cluster
            agent_pools = []
            try:
                pool_iterator = aks_client.agent_pools.list(resource_group, cluster.name)
                for pool in pool_iterator:
                    logging.info("  - Found agent pool '%s'.", pool.name)
                    agent_pools.append(pool.as_dict())               
            except HttpResponseError as e:
                 logging.error("Could not describe agent pools for %s in %s: %s", cluster.name, cluster.resource_group, e)

            cluster_details['agentPools'] = agent_pools
            clusters_data.append(cluster_details)

        return clusters_data
    except HttpResponseError as e:
        # Handles subscriptions where the resource provider might not be registered
        logging.warning("Could not access AKS in subscription %s. Skipping. Error: %s", subscription_id, e)
        return []
    except Exception as e:
        logging.error("An unexpected error occurred while scanning subscription %s: %s", subscription_id, e)
        return []

def json_serial(obj):
    """JSON serializer for objects not serializable by default, like datetime."""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def main():
    parser = argparse.ArgumentParser(description="Fetch AKS cluster data from Azure.")
    parser.add_argument('--subscription-ids', nargs='*', help='Specific Azure subscription IDs to scan. If not provided, all accessible subscriptions will be scanned.')
    parser.add_argument('--output-file', default='aks_data.json', help='The file to write the JSON output to.')
    args = parser.parse_args()

    try:
        credential = DefaultAzureCredential()
        # A quick check to fail early if auth is not configured
        credential.get_token("https://management.azure.com/.default")
    except Exception as e:
        logging.error("Failed to acquire a token. Please check your Azure authentication setup (e.g., 'az login'). Error: %s", e)
        return

    subscriptions_to_scan = args.subscription_ids or get_available_subscriptions(credential)
    print( f"Subscriptions : {subscriptions_to_scan}")
    if not subscriptions_to_scan:
        logging.warning("No subscriptions found or specified to scan.")
        return

    logging.info("Starting AKS discovery for subscriptions: %s", subscriptions_to_scan)

    all_aks_data = []
    for sub_id in subscriptions_to_scan:
        all_aks_data.extend(get_aks_data_for_subscription(credential, sub_id))

    if all_aks_data:
        output_dir = os.path.dirname(args.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(args.output_file, 'w', encoding='utf-8') as f:
            json.dump(all_aks_data, f, indent=4, default=json_serial)
        logging.info("Successfully wrote AKS data to %s", args.output_file)
    else:
        logging.info("No AKS data found across scanned subscriptions.")

if __name__ == "__main__":
    main()