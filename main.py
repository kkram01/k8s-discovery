import typer
import aws_discover, azure_discover, gke_discover, common

app = typer.Typer(
    no_args_is_help=True
)

@app.command()
def aws(
    region: str = typer.Option(..., help="The AWS region to scan for EKS clusters."),
    output_file: str = typer.Option(None, help="The path to save the output CSV file.")
):
    """
    Discover EKS clusters in a specific AWS region.
    """
    print(f"Discovering AWS EKS clusters in region: {region}")
    clusters = aws_discover.discover_eks_resources(region)
    if clusters:
        common.display_data("AWS EKS Clusters", clusters)
        if output_file:
            common.save_to_csv(output_file, clusters)

@app.command()
def azure(
    subscription_id: str = typer.Option(..., help="The Azure subscription ID to scan for AKS clusters."),
    output_file: str = typer.Option(None, help="The path to save the output CSV file.")
):
    """
    Discover AKS clusters in a specific Azure subscription.
    """
    print(f"Discovering Azure AKS clusters in subscription: {subscription_id}")
    clusters = azure_discover.discover_aks_resources(subscription_id)
    if clusters:
        common.display_data("Azure AKS Clusters", clusters)
        if output_file:
            common.save_to_csv(output_file, clusters)

@app.command()
def gke(
    output_dir: str = typer.Option("./gke_output", help="The directory to save the output CSV files.")
):
    """
    Discover resources in the currently configured GKE cluster.
    """
    print("Discovering resources in your currently configured GKE cluster...")
    resources = gke_discover.discover_gke_resources()
    if resources:
        for name, data in resources.items():
            if data:
                common.display_data(f"GKE {name.capitalize()}", data)
                common.save_to_csv(f"{output_dir}/{name}.csv", data)

if __name__ == "__main__":
    app()
