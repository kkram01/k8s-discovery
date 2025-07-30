import argparse
import datetime
import json
import logging
import os
import boto3

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_available_regions(service_name):
    session = boto3.Session()
    return session.get_available_regions(service_name)

def get_eks_data_for_region(region):
    logging.info("Scanning EKS clusters in region: %s", region)
    try:
        eks_client = boto3.client('eks', region_name=region)
        clusters_data = []

        # Paginate through all clusters in the region
        paginator = eks_client.get_paginator('list_clusters')
        for page in paginator.paginate():
            for cluster_name in page['clusters']:
                logging.info("Found cluster '%s'. Getting details...", cluster_name)
                cluster_details = eks_client.describe_cluster(name=cluster_name)['cluster']

                # Get nodegroups for the cluster
                nodegroups = []
                try:
                    nodegroup_paginator = eks_client.get_paginator('list_nodegroups')
                    for ng_page in nodegroup_paginator.paginate(clusterName=cluster_name):
                        for nodegroup_name in ng_page['nodegroups']:
                            logging.info("  - Found nodegroup '%s'. Getting details...", nodegroup_name)
                            nodegroup_details = eks_client.describe_nodegroup(
                                clusterName=cluster_name,
                                nodegroupName=nodegroup_name
                            )['nodegroup']
                            nodegroups.append(nodegroup_details)
                except Exception as e:
                    logging.error("Could not describe nodegroups for %s in %s: %s", cluster_name, region, e)

                cluster_details['nodegroups'] = nodegroups
                clusters_data.append(cluster_details)

        return clusters_data
    except Exception as e:
        # Handles regions where EKS might not be enabled or accessible.
        logging.warning("Could not access EKS in region %s. Skipping. Error: %s", region, e)
        return []

def json_serial(obj):
    """JSON serializer for objects not serializable by default, like datetime."""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def main():
    parser = argparse.ArgumentParser(description="Fetch EKS cluster data from AWS.")
    parser.add_argument('--regions', nargs='*', help='Specific AWS regions to scan. If not provided, all available EKS regions will be scanned.')
    parser.add_argument('--output-file', default='eks_data.json', help='The file to write the JSON output to.')
    args = parser.parse_args()

    regions_to_scan = args.regions or get_available_regions('eks')
    logging.info("Starting EKS discovery for regions: %s", regions_to_scan)

    all_eks_data = []
    for region in regions_to_scan:
        all_eks_data.extend(get_eks_data_for_region(region))

    if all_eks_data:
        output_dir = os.path.dirname(args.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(args.output_file, 'w', encoding='utf-8') as f:
            json.dump(all_eks_data, f, indent=4, default=json_serial)
        logging.info("Successfully wrote EKS data to %s", args.output_file)
    else:
        logging.info("No EKS data found across scanned regions.")

if __name__ == "__main__":
    main()

