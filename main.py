import typer
import eks_discovery, aks_discovery, k8s_resources, common
import boto3
import json
import logging
from azure.identity import DefaultAzureCredential

app = typer.Typer(
    no_args_is_help=True
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

@app.command()
def aws(
    regions: list[str] = typer.Option(None, "--region", help="Specific AWS regions to scan. If empty, all available EKS regions will be scanned."),
    output_file: str = typer.Option("eks_data.json", help="The path to save the output JSON file.")
):
    """
    Discover EKS clusters in specific or all AWS regions with detailed information.
    """
    session = boto3.Session()
    regions_to_scan = regions or eks_discovery.get_available_regions(session, "eks")
    logging.info("Starting EKS discovery for regions: %s", regions_to_scan)

    all_eks_data = eks_discovery.run_eks_discovery(session, regions_to_scan)

    if all_eks_data:
        logging.info(f"Found a total of {len(all_eks_data)} EKS clusters across all scanned regions.")
        if output_file:
            common.save_to_json(all_eks_data, output_file)
    else:
        logging.info("No EKS data found across scanned regions.")

@app.command()
def azure(
    subscription_ids: list[str] = typer.Option(None, "--subscription-id", help="Specific Azure subscription IDs to scan. If empty, all accessible subscriptions will be scanned."),
    output_file: str = typer.Option("aks_data.json", help="The path to save the output JSON file.")
):
    """
    Discover AKS clusters in specific or all Azure subscriptions with detailed information.
    """
    try:
        credential = DefaultAzureCredential()
        # Test credential
        credential.get_token("https://management.azure.com/.default")
    except Exception as e:
        logging.error("Failed to acquire a token. Please check your Azure authentication setup (e.g., 'az login'). Error: %s", e)
        return

    subscriptions_to_scan = subscription_ids or aks_discovery.get_available_subscriptions(credential)
    if not subscriptions_to_scan:
        logging.warning("No subscriptions found or specified to scan.")
        return

    logging.info("Starting AKS discovery for subscriptions: %s", subscriptions_to_scan)

    all_aks_data = aks_discovery.run_aks_discovery(credential, subscriptions_to_scan)

    if all_aks_data:
        logging.info(f"Found a total of {len(all_aks_data)} AKS clusters across all scanned subscriptions.")
        if output_file:
            common.save_to_json(all_aks_data, output_file)
    else:
        logging.info("No AKS data found across scanned subscriptions.")

@app.command()
def gke(
    output_dir: str = typer.Option("./gke_output", help="The directory to save the output CSV files.")
):
    """
    Discover resources in the currently configured GKE cluster.
    """
    print("Discovering resources in your currently configured GKE cluster...")
    # GKE discovery does not have a cloud-level discovery part like EKS/AKS.
    # We will directly fetch Kubernetes details.
    kubernetes_details = k8s_resources.get_k8s_details_for_gke()

    if kubernetes_details and "error" not in kubernetes_details:
        # For consistency, we'll wrap the output in the same structure.
        # "hosting_provider_details" can be minimal for GKE as we connect directly.
        final_gke_data = [{
            "hosting_provider_details": {"provider": "gke", "cluster_name": "current-context"},
            "kubernetes_details": kubernetes_details
        }]

        output_file = f"{output_dir}/gke_data.json"
        common.save_to_json(final_gke_data, output_file)

if __name__ == "__main__":
    app()
