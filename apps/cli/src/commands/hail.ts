import { Command } from "commander";
import { runCommand } from "../lib/command-helpers.js";
import { handleHail } from "../lib/hail-handlers.js";

export const hailCommand = new Command("hail")
  .description("Bring all vault data in the active organization")
  .action(() => runCommand(() => handleHail()));
