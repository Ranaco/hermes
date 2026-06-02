import { requireActiveOrganization } from "./context.js";
import { renderData, requireAuth } from "./command-helpers.js";
import * as sdk from "./sdk.js";
import * as ui from "./ui.js";

/**
 * Constants for bulk data retrieval
 */
const FETCH_BATCH_SIZE = 5;
const SECRETS_PAGE_LIMIT = 100;

/**
 * Explicit type for vault with its secrets
 */
export interface VaultWithSecrets extends sdk.VaultSummary {
  secrets: sdk.SecretSummary[];
}

/**
 * Fetches all secrets for a given vault, handling pagination
 */
async function fetchAllSecrets(vaultId: string): Promise<sdk.SecretSummary[]> {
  const allSecrets: sdk.SecretSummary[] = [];
  let page = 1;
  let hasMore = true;

  while (hasMore) {
    const secrets = await sdk.getSecrets(vaultId, {
      page,
      limit: SECRETS_PAGE_LIMIT,
      cliScope: true,
    });

    allSecrets.push(...secrets);

    // If we received fewer secrets than the limit, we've reached the end
    if (secrets.length < SECRETS_PAGE_LIMIT) {
      hasMore = false;
    } else {
      page++;
    }
  }

  return allSecrets;
}

/**
 * Fetches all vaults and their secrets for an organization
 */
export async function fetchAllVaultData(organizationId: string): Promise<VaultWithSecrets[]> {
  const vaults = await sdk.getVaults(organizationId);
  const allData: VaultWithSecrets[] = [];

  // Process vaults in batches to avoid overwhelming the server
  for (let i = 0; i < vaults.length; i += FETCH_BATCH_SIZE) {
    const batch = vaults.slice(i, i + FETCH_BATCH_SIZE);
    const batchResults = await Promise.allSettled(
      batch.map(async (vault) => {
        const secrets = await fetchAllSecrets(vault.id);
        return {
          ...vault,
          secrets,
        };
      }),
    );

    for (const result of batchResults) {
      if (result.status === "fulfilled") {
        allData.push(result.value);
      } else {
        // Log the error but allow the overall command to continue
        ui.error(`Failed to fetch data for one of the vaults: ${result.reason}`);
      }
    }
  }

  return allData;
}

/**
 * Handler for the 'hail' command
 */
export async function handleHail(): Promise<void> {
  requireAuth();

  const organization = await requireActiveOrganization();
  const status = ui.status(`Fetching all data for ${organization.name}...`);

  try {
    const vaultsWithSecrets = await fetchAllVaultData(organization.id);

    status.succeed(`Retrieved data from ${vaultsWithSecrets.length} vaults`);

    // Render machine-readable output if requested (e.g. via --json)
    renderData({ success: true, organization, vaults: vaultsWithSecrets });

    if (vaultsWithSecrets.length === 0) {
      ui.warn("No vaults found in this organization.");
      ui.newline();
      return;
    }

    // Build tree items for UI display
    const treeItems: ui.NestedTreeItem[] = vaultsWithSecrets.map((vault) => ({
      name: vault.name,
      id: vault.id,
      isGroup: true,
      meta: `${vault.secrets.length} secrets`,
      children: vault.secrets.map((secret) => ({
        name: secret.name,
        id: secret.id,
        isGroup: false,
        meta: secret.valueType,
      })),
    }));

    ui.nestedTreeListing(`Organization: ${organization.name}`, treeItems);
  } catch (error) {
    status.fail("Failed to retrieve vault data");
    throw error;
  }
}
