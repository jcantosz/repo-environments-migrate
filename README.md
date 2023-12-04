## Migration Repository Environments Action

`jcantosz/repo-environments-migrate`

This action migrates a repository's environment and its settings to another repository.

### Inputs

`reviewer_mapping_file`
**Required** The path to the reviewer mapping file. This file should map source reviewer usernames to target reviewer usernames.

`org_mapping_file`
**Required** The path to the organization mapping file. This file should map source organization names to target organization names.

`source_repo`
**Required** The URL of the source repository.

`source_github_app_id`
**Required** The ID of the source GitHub App.

`source_github_app_private_key`
**Required** The private key of the source GitHub App.

`source_github_app_installation_id`
**Required** The installation ID of the source GitHub App.

`source_github_api_url`
The API URL of the source GitHub. Default is https://api.github.com.

`target_github_app_id`
The ID of the target GitHub App. If not provided, the source GitHub App ID is used.

`target_github_app_private_key`
The private key of the target GitHub App. If not provided, the source GitHub App private key is used.

`target_github_app_installation_id`
The installation ID of the target GitHub App. If not provided, the source GitHub App installation ID is used.

`target_github_api_url`
The API URL of the target GitHub. If not provided, the source GitHub API URL is used.

`migration_type`
The type of migration (what type of csv files to expect). `gei` or non-gei

### Usage

You can use this action in a workflow file with the uses keyword:

```yaml
steps:
  - name: Checkout code
    uses: actions/checkout@v4

  - name: Run Migration Repository Environments Action
    uses: jcantosz/repo-environments-migrate@v1
    with:
      reviewer_mapping_file: "reviewer_mapping.csv"
      org_mapping_file: "org_mapping.csv"
      source_repo: "https://github.com/org/repo1,https://github.com/org/repo2"
      source_github_app_id: ${{ secrets.SOURCE_GITHUB_APP_ID }}
      source_github_app_private_key: ${{ secrets.SOURCE_GITHUB_APP_PRIVATE_KEY }}
      source_github_app_installation_id: ${{ secrets.SOURCE_GITHUB_APP_INSTALLATION_ID }}
      target_github_app_id: ${{ secrets.TARGET_GITHUB_APP_ID }}
      target_github_app_private_key: ${{ secrets.TARGET_GITHUB_APP_PRIVATE_KEY }}
      target_github_app_installation_id: ${{ secrets.TARGET_GITHUB_APP_INSTALLATION_ID }}
      migration_type: "gei"
```

## Description

This JavaScript code is designed to be used as a GitHub Action. It reads mappings from two CSV files, fetches environment data from a source GitHub repository, and creates or updates corresponding environments in a target GitHub repository.

Step-by-step usage guide:

1. Prepare two CSV files for organization and reviewer mappings. The organization mapping file should map source organization names to target organization names. The reviewer mapping file should map source reviewer usernames to target reviewer usernames.

1. Set up the necessary secrets in your GitHub repository settings. These should include the paths to your mapping files, the URLs of your source repositories, and the credentials for your source and target GitHub Apps.

1. Create a new GitHub Action workflow file in your repository's .github/workflows directory. In this workflow file, use this JavaScript code as a step. You can use the actions/github-script action to run this code.

1. In the workflow file, pass the necessary inputs to the script. These should include the paths to your mapping files, the URLs of your source repositories, and the credentials for your source and target GitHub Apps.

1. Commit and push your changes to the repository. The workflow will run on the event specified in the workflow file (e.g., on every push to the main branch).

The code works as follows:

- It reads the action inputs, which include the paths to the mapping files, the URLs of the source repositories, and the credentials for the source and target GitHub Apps.

- It creates Octokit instances for the source and target GitHub Apps. Octokit is a client library for the GitHub API.

- It defines several helper functions for getting environments from a repository, getting mappings from a CSV file, creating or updating environments in a repository, and mapping organization names and reviewer usernames.

- In the main function, it gets the organization mapping, loops over the source repositories, maps the organization names, and creates or updates the environments in the target repository.

- If any environments fail to be created or updated, it logs an error message with the names of these environments.
