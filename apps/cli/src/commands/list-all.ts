import { Command } from "commander";
import { requireActiveOrganization } from "../lib/context.js";
import { renderData, requireAuth, runCommand } from "../lib/command-helpers.js";
import * as sdk from "../lib/sdk.js";
import * as ui from "../lib/ui.js";

export const listAllCommand = new Command("listAll")
  .description("List all vaults and keys in the active organization")
  .action(() =>
    runCommand(async () => {
      requireAuth();
      const organization = await requireActiveOrganization();
      const vaults = await sdk.getVaults(organization.id);

      const allData = await Promise.all(
        vaults.map(async (vault) => {
          const keys = await sdk.getKeys(vault.id);
          return { ...vault, keys };
        }),
      );

      renderData({ organization, vaults: allData });

      if (vaults.length === 0) {
        ui.warn("No vaults found");
        ui.newline();
        return;
      }

      for (const vault of allData) {
        ui.panel(`Vault: ${vault.name} (${ui.shortId(vault.id)})`, [
          ...(vault.description ? [ui.kv("Description", vault.description)] : []),
          ui.kv("Keys", String(vault.keys.length)),
        ]);

        if (vault.keys.length > 0) {
          ui.cards(
            vault.keys.map((key) => ({
              id: key.id,
              name: key.name,
              fields: [
                { label: "Type", value: key.valueType || "STRING", overflow: "truncate" },
                { label: "Versions", value: String(key._count?.versions || key.versions?.length || 1), overflow: "truncate" },
              ],
            })),
          );
        } else {
          ui.info("No keys in this vault");
          ui.newline();
        }
      }
    }),
  );
