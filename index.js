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
const sourceRepos = core.getInput("source_repos").split(",");
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

core.info(`isDebug? ${core.isDebug()}`);

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
    log: core.isDebug() ? console : null,
  });
}

async function getEnvironments(owner, repo) {
  try {
    const response = await sourceOctokit.repos.getAllEnvironments({ owner, repo });
    return response.data.environments;
  } catch (error) {
    console.error(error);
  }
}

async function usernameToID(username) {
  const userObj = await targetOctokit.request("GET /users/{username}", {
    username: username,
    headers: {
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  return userObj.data.id;
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

async function usernameToUsernameMap(file) {
  core.info(`\treading reviewers from ${file}`);
  if (mapType == "gei") {
    core.info(`\tIn GEI format (headers mannequin-user, target-user)`);
    return getMapping(file, "mannequin-user", "target-user");
  } else {
    core.info(`\tIn non-GEI format (headers source, target)`);
    return getMapping(file, "source", "target");
  }
}

async function getReviewerMapping(file) {
  let usernameMapping = await usernameToUsernameMap(file);
  for (const [key, value] of Object.entries(usernameMapping)) {
    console.log(`Trying to get ID for user: ${value}`);
    usernameMapping[key] = await usernameToID(value);
  }
  return usernameMapping;
}

// Function to get environments from source GitHub instance
async function createEnvironments(sourceOwner, sourceRepo, targetOwner, targetRepo) {
  try {
    core.info(`\tGetting environments for "${sourceOwner}/${sourceRepo}"`);
    const environments = await getEnvironments(sourceOwner, sourceRepo);
    core.debug(`\tFound environment(s): ${JSON.stringify(environments)}`);
    const reviewerMapping = await getReviewerMapping(reviewerMappingFile);

    core.info(`\treviewer mapping: ${JSON.stringify(reviewerMapping)}`);
    core.info(`\n`);

    for (const environment of environments) {
      core.info(`\tProcessing "${environment.name}" environment`);
      await createOrUpdateEnvironment(sourceOwner, targetOwner, targetRepo, environment, reviewerMapping);

      core.info(`\n`);
    }
    // const promises = environments.map((environment) =>
    //   createOrUpdateEnvironment(
    //     targetOwner,
    //     targetRepo,
    //     environment,
    //     mapReviewers(environment.reviewers, reviewerMapping)
    //   )
    // );
    // // create all environments in destintaion in parallel
    // const results = await Promise.all(promises);

    // Get all failed results and return them
    // const failedEnvironments = results.filter((result) => result !== null);
    // return failedEnvironments;
  } catch (error) {
    console.error(error);
  }
}

// Function to map organization names based on orgMapping
function mapOrgs(org, orgMapping) {
  return orgMapping[org] || org;
}

//https://docs.github.com/en/rest/deployments/branch-policies?apiVersion=2022-11-28#get-a-deployment-branch-policy
//https://octokit.github.io/rest.js/v20
async function getDeploymentBranchPolicy(owner, repo, environment_name) {
  core.info(`Reading branch protection rules ${owner}/${repo}:${environment_name}`);
  var protectionRules = await sourceOctokit.rest.repos.listDeploymentBranchPolicies({
    owner: owner,
    repo: repo,
    environment_name: environment_name,
  });
  return protectionRules.data;
}
async function createDeploymentBranchPolicy(policy) {
  return await targetOctokit.rest.repos.createDeploymentBranchPolicy(policy);
}
// Function to get reviewer mapping from file
function mapReviewers(reviewers, reviewerMapping) {
  var mappedReviewers = [];
  for (const reviewer of reviewers) {
    const type = reviewer.type;
    // read slug prop if it's a team, else read login (it's a user)
    const name = type == "Team" ? reviewer.reviewer.slug : reviewer.reviewer.login;
    core.debug(`Mapping user with properties type: ${type}, name: ${name}`);
    mappedReviewers.push({ type: type, id: reviewerMapping[name] || name });
  }
  console.log(mappedReviewers);
  return mappedReviewers;
}

async function createOrUpdateEnvironment(sourceOwner, targetOwner, targetRepo, environment, reviewerMapping) {
  try {
    const protectionRules = environment.protection_rules || null;
    var reviewers = [];
    var wait_timer = 0;
    var branchProtectionRules = [];
    var hasProtectionRules = false;
    // unfurl protection rules
    if (protectionRules) {
      for (rule of protectionRules) {
        if (rule.type == "wait_timer") {
          wait_timer = rule.wait_timer;
          core.debug(`Read wait time from source ${wait_timer}`);
        } else if (rule.type == "required_reviewers") {
          reviewers = mapReviewers(rule.reviewers, reviewerMapping);
          core.debug(`Read and mapped reviewers from source ${JSON.stringify(reviewers)}`);
        } else if ((rule.type = "branch_policy")) {
          hasProtectionRules = true;
          core.info(`Environment has branch protectionpolicy`);
        } else {
          core.warning(`Rule not accounted for, skipping: ${JSON.stringify(rule)}`);
        }
      }
    }

    if (hasProtectionRules && environment.deployment_branch_policy.custom_branch_policies) {
      core.info(`Reading branch protection Polciies`);
      var policies = await getDeploymentBranchPolicy(sourceOwner, targetRepo, environment.name);
      for (policy of policies.branch_policies) {
        branchProtectionRules.push({
          owner: targetOwner,
          repo: targetRepo,
          environment_name: environment.name,
          name: policy.name,
        });
      }
    }
    console.debug(`Branch Protection Rules: ${JSON.stringify(branchProtectionRules)}`);
    core.info(`\tCreating environment ${targetOwner}/${targetRepo}: ${environment.name}`);
    core.info(
      `\tProperties:` +
        `\n\t\towner: ${targetOwner},` +
        `\n\t\trepo: ${targetRepo},` +
        `\n\t\tenvironment_name: ${environment.name},` +
        `\n\t\twait_timer: ${wait_timer},` +
        `\n\t\tprevent_self_review: ${environment.prevent_self_review},` +
        `\n\t\treviewers: ${JSON.stringify(reviewers)},` +
        `\n\t\tdeployment_branch_policy: ${JSON.stringify(environment.deployment_branch_policy)},`
    );

    // TODO: Need to map reviwers and groups to IDs of users (name not allowed)
    // TODO: Set allow admin bypass setting on deployment
    // TODO: Handle protected branches (instead of just globbed branch names)
    await targetOctokit.repos.createOrUpdateEnvironment({
      owner: targetOwner,
      repo: targetRepo,
      environment_name: environment.name,
      wait_timer: wait_timer,
      prevent_self_review: environment.prevent_self_review,
      reviewers: reviewers,
      deployment_branch_policy: environment.deployment_branch_policy,
    });

    // Iterate through and create protection rules after env is created
    for (policy of branchProtectionRules) {
      core.info(`\t\t Adding protection rule for: "${policy.name}"`);
      await createDeploymentBranchPolicy(policy);
    }

    return null;
  } catch (error) {
    console.error(`Failed to create or update environment "${environment.name}": ${error.message}`);
    return `${targetOwner}/${targetRepo}:${environment.name}`;
  }
}

async function main() {
  const orgMapping = await getOrgMapping(orgMappingFile);
  core.info(`Mapped orgs: ${JSON.stringify(orgMapping)}`);
  core.info(`Repos to process: ${sourceRepos}\n`);
  for (const sourceRepo of sourceRepos) {
    core.info(`Processing repo: ${sourceRepo}`);
    // expect repo to be of the form https://something.com/other/path/things/ORG/REPO
    const [sourceOrg, repo] = sourceRepo.split("/").slice(-2);
    const targetOrg = mapOrgs(sourceOrg, orgMapping);

    core.info(`Mapping environments ${sourceOrg}/${repo} -> ${targetOrg}/${repo}`);
    // let user = await usernameToID("jcantosz");
    // console.log(`jcantosz: ${JSON.stringify(user)}`);
    await createEnvironments(sourceOrg, repo, targetOrg, repo);
    // const failedEnvironments = await createEnvironments(sourceOrg, repo, targetOrg, repo);
    // if (failedEnvironments.length > 0) {
    //   console.error(`Failed to create or update the following environments: ${failedEnvironments.join(", ")}`);
    // }
  }
}

main();
