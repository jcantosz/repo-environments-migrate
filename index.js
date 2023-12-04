// Import required libraries
const fs = require("fs");
const csv = require("csv-parser");
const { Octokit } = require("@octokit/rest");
const { createAppAuth } = require("@octokit/auth-app");
const core = require("@actions/core");

// Get action inputs
const reviewerMappingFile = core.getInput("reviewer_mapping_file");
const orgMappingFile = core.getInput("org_mapping_file");

// repo of the form https://github.com/org/repo
const sourceRepos = core.getInput("source_repo").split(",");
const mapType = core.getInput("migration_type").toLowerCase();

// Get GitHub source and destination inputs
const sourceAppId = core.getInput("source_github_app_id");
const sourceAppPrivateKey = core.getInput("source_github_app_private_key");
const sourceAppInstallationId = core.getInput("source_github_app_installation_id");
const sourceAPIUrl = core.getInput("source_github_api_url") || "https://api.github.com";

const targetAppId = core.getInput("target_github_app_id") || sourceAppId;
const targetAppPrivateKey = core.getInput("target_github_app_private_key") || sourceAppPrivateKey;
const targetAppInstallationId = core.getInput("target_github_app_installation_id") || sourceAppInstallationId;
const targetAPIUrl = core.getInput("target_github_api_url") || sourceAPIUrl;

// Create Octokit instances for source and target
const sourceOctokit = createOctokitInstance(sourceAppId, sourceAppPrivateKey, sourceAppInstallationId, sourceAPIUrl);
const targetOctokit = createOctokitInstance(targetAppId, targetAppPrivateKey, targetAppInstallationId, targetAPIUrl);

// Function to create Octokit instance
function createOctokitInstance(appId, appPrivateKey, appInstallationId, apiUrl) {
  return new Octokit({
    authStrategy: createAppAuth,
    auth: {
      appId: appId,
      privateKey: appPrivateKey,
      installationId: appInstallationId,
    },
    baseUrl: apiUrl,
  });
}

async function getEnvironments(owner, repo) {
  try {
    const response = await sourceOctokit.repos.get({ owner, repo });
    return response.data.environments;
  } catch (error) {
    console.error(error);
  }
}

async function getMapping(file, sourceColumn, targetColumn) {
  const mapping = {};
  return new Promise((resolve, reject) => {
    fs.createReadStream(file)
      .pipe(csv())
      .on("data", (row) => {
        mapping[row[sourceColumn]] = row[targetColumn];
      })
      .on("end", () => {
        resolve(mapping);
      })
      .on("error", reject);
  });
}

async function getOrgMapping(file) {
  return getMapping(file, "source", "target");
}

async function getReviewierMapping(file) {
  if (mapType == "gei") {
    return getMapping(file, "mannequin-user", "target-user");
  } else {
    return getMapping(file, "sourceReviewer", "targetReviewer");
  }
}

// Function to get environments from source GitHub instance
async function createEnvironments(sourceOwner, sourceRepo, targetOwner, targetRepo) {
  try {
    const environments = await getEnvironments(sourceOwner, sourceRepo);
    const reviewerMapping = await getReviewerMapping(reviewerMappingFile);
    const promises = environments.map((environment) =>
      createOrUpdateEnvironment(
        targetOwner,
        targetRepo,
        environment,
        mapReviewers(environment.reviewers, reviewerMapping)
      )
    );
    // create all environments in destintaion in parallel
    const results = await Promise.all(promises);

    // Get all failed results and return them
    const failedEnvironments = results.filter((result) => result !== null);
    return failedEnvironments;
  } catch (error) {
    console.error(error);
  }
}

// Function to map organization names based on orgMapping
function mapOrgs(org, orgMapping) {
  return orgMapping[org] || org;
}

// Function to get reviewer mapping from file
function mapReviewers(reviewers, reviewerMapping) {
  return reviewers.map((reviewer) => reviewerMapping[reviewer.login] || reviewer.login);
}

async function createOrUpdateEnvironment(targetOwner, targetRepo, environment, reviewers) {
  try {
    console.log(`Creating environment ${targetOwner}/${targetRepo}: ${environment.name}`);
    await targetOctokit.repos.createOrUpdateEnvironment({
      owner: targetOwner,
      repo: targetRepo,
      name: environment.name,
      wait_timer: environment.wait_timer,
      reviewers,
      deployment_branch_policy: environment.deployment_branch_policy,
      environment_protection_rules: environment.environment_protection_rules,
    });
    return null;
  } catch (error) {
    console.error(`Failed to create or update environment ${environment.name}: ${error.message}`);
    return `${targetOwner}/${targetRepo}:${environment.name}`;
  }
}

async function main() {
  const orgMapping = await getOrgMapping(orgMappingFile);
  for (const sourceRepo of sourceRepos) {
    // expect repo to be of the form https://something.com/other/path/things/ORG/REPO
    const [sourceOrg, repo] = sourceRepo.split("/").slice(-2);
    const targetOrg = mapOrgs(sourceOrg, orgMapping);

    const failedEnvironments = await createEnvironments(sourceOwner, repo, targetOrg, repo);
    if (failedEnvironments.length > 0) {
      console.error(`Failed to create or update the following environments: ${failedEnvironments.join(", ")}`);
    }
  }
}

main();
