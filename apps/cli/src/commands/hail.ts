import { Command } from "commander";
import { runCommand } from "../lib/command-helpers.js";
import { handleHail } from "../lib/hail-handlers.js";

export const hailCommand = new Command("hail")
  .description("Retrieve all vault data and secrets in the active organization")
  .action(() => runCommand(() => handleHail()));
