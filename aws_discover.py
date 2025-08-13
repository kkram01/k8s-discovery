import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

def get_eks_clusters(region: str):
    """
    Fetches EKS cluster data from a specific AWS region.
    """
    try:
        eks_client = boto3.client('eks', region_name=region)
        paginator = eks_client.get_paginator('list_clusters')
        clusters_data = []

        for page in paginator.paginate():
            for cluster_name in page['clusters']:
                cluster_details = eks_client.describe_cluster(name=cluster_name)['cluster']
                clusters_data.append({
                    'name': cluster_details['name'],
                    'arn': cluster_details['arn'],
                    'version': cluster_details['version'],
                    'status': cluster_details['status'],
                    'endpoint': cluster_details.get('endpoint', 'N/A'),
                })
        return clusters_data

    except (NoCredentialsError, PartialCredentialsError):
        print("AWS credentials not found. Please configure your credentials.")
        return []
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print(f"Access denied in region {region}. Please check your IAM permissions.")
        else:
            print(f"An AWS client error occurred in {region}: {e}")
        return []


def discover_eks_resources(region: str):
    """
    Discover all EKS clusters in a given region.
    """
    if region:
        return get_eks_clusters(region)
    else:
        # If no region is specified, you might want to scan all available regions
        print("No AWS region specified. Please use the --region option.")
        return []
