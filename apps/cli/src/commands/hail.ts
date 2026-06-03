import { Command } from "commander";
import { requireActiveOrganization } from "../lib/context.js";
import { renderData, requireAuth, runCommand } from "../lib/command-helpers.js";
import * as sdk from "../lib/sdk.js";
import * as ui from "../lib/ui.js";

export const hailCommand = new Command("hail")
  .description("Bring all vault data")
  .action(() =>
    runCommand(async () => {
      requireAuth();
      const organization = await requireActiveOrganization();
      
      const s = ui.status("Gathering vault data...");
      const vaults = await sdk.getVaults(organization.id);
      
      const allData = [];
      for (const vault of vaults) {
        s.update(`Fetching secrets from ${vault.name}...`);
        const secrets = await sdk.getSecrets(vault.id, { cliScope: true });
        allData.push({ vault, secrets });
      }
      s.stop();

      renderData({ organization, vaults: allData });
      
      await ui.banner();
      
      const treeItems: ui.NestedTreeItem[] = allData.map(({ vault, secrets }) => ({
        name: vault.name,
        id: vault.id,
        isGroup: true,
        meta: `${secrets.length} secrets`,
        children: secrets.map((secret) => ({
          name: secret.name,
          id: secret.id,
          isGroup: false,
          meta: `${secret.valueType || "STRING"}  v${secret.currentVersion?.versionNumber || 1}`,
        })),
      }));

      ui.nestedTreeListing(`${organization.name} Vaults`, treeItems);
      
      ui.success(`Brought data from ${vaults.length} vaults`);
      ui.newline();
    }),
  );
