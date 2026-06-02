import { requireActiveOrganization } from "./context.js";
import { renderData, requireAuth } from "./command-helpers.js";
import * as sdk from "./sdk.js";
import * as ui from "./ui.js";

export async function handleHail(): Promise<void> {
  requireAuth();

  const organization = await requireActiveOrganization();
  const status = ui.status(`Fetching all data for ${organization.name}...`);

  try {
    const vaults = await sdk.getVaults(organization.id);
    const allData = [];
    const BATCH_SIZE = 5;

    for (let i = 0; i < vaults.length; i += BATCH_SIZE) {
      const batch = vaults.slice(i, i + BATCH_SIZE);
      const batchResults = await Promise.all(
        batch.map(async (vault) => {
          const secrets = await sdk.getSecrets(vault.id, { cliScope: true });
          return {
            ...vault,
            secrets,
          };
        }),
      );
      allData.push(...batchResults);
    }

    status.succeed(`Retrieved data from ${vaults.length} vaults`);

    renderData({ success: true, organization, vaults: allData });

    if (allData.length === 0) {
      ui.warn("No vaults found in this organization.");
      ui.newline();
      return;
    }

    const treeItems: ui.NestedTreeItem[] = allData.map((vault) => ({
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
