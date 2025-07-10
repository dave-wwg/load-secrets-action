import * as core from "@actions/core";
import * as exec from "@actions/exec";
import { read, setClientInfo, semverToInt } from "@1password/op-js";
import { version } from "../package.json";
import {
	authErr,
	envConnectHost,
	envConnectToken,
	envServiceAccountToken,
	envManagedVariables,
	envVaultItem,
} from "./constants";

export const validateAuth = (): void => {
	const isConnect = process.env[envConnectHost] && process.env[envConnectToken];
	const isServiceAccount = process.env[envServiceAccountToken];

	if (isConnect && isServiceAccount) {
		core.warning(
			"WARNING: Both service account and Connect credentials are provided. Connect credentials will take priority.",
		);
	}

	if (!isConnect && !isServiceAccount) {
		throw new Error(authErr);
	}

	const authType = isConnect ? "Connect" : "Service account";

	core.info(`Authenticated with ${authType}.`);
};

export const extractSecret = (
	envName: string,
	shouldExportEnv: boolean,
): void => {
	core.info(`Populating variable: ${envName}`);

	const ref = process.env[envName];
	if (!ref) {
		return;
	}

	const secretValue = read.parse(ref);
	if (!secretValue) {
		return;
	}

	if (shouldExportEnv) {
		core.exportVariable(envName, secretValue);
	} else {
		core.setOutput(envName, secretValue);
	}
	core.setSecret(secretValue);
};

export const loadSecrets = async (shouldExportEnv: boolean): Promise<void> => {
	// Pass User-Agent Information to the 1Password CLI
	setClientInfo({
		name: "1Password GitHub Action",
		id: "GHA",
		build: semverToInt(version),
	});

	const vaultItem = process.env[envVaultItem];
	if (vaultItem) {
		if (!vaultItem.match(/^op:\/\/vault\/(?!item\/).*$/)) {
			throw new Error(`Invalid vault item format: ${vaultItem}`);
		}

		core.info(`Loading all secrets from vault item: ${vaultItem}`);
		const res = await exec.getExecOutput(`sh -c "op item get ${vaultItem} --reveal"`);
		
		if (res.stdout) {
			const lines = res.stdout.split('\n');
			let inFieldsSection = false;
			const vaultEnvs: string[] = [];
			
			for (const line of lines) {
				if (line.trim() === 'Fields:') {
					inFieldsSection = true;
					continue;
				}
				
				if (inFieldsSection && line.trim() === '') {
					// Empty line might end the Fields section
					continue;
				}
				
				if (inFieldsSection && line.startsWith('  ')) {
					// This is a field line
					const match = line.match(/^\s+([^:]+):\s*(.*)$/);
					if (match && match[1] && match[2] !== undefined) {
						const fieldName = match[1].trim();
						const fieldValue = match[2].trim();
						
						// Skip notesPlain field
						if (fieldName === 'notesPlain') {
							continue;
						}
						
						core.info(`Loading secret: ${fieldName}`);
						
						if (shouldExportEnv) {
							core.exportVariable(fieldName, fieldValue);
						} else {
							core.setOutput(fieldName, fieldValue);
						}
						core.setSecret(fieldValue);
						vaultEnvs.push(fieldName);
					}
				} else if (inFieldsSection && !line.startsWith('  ')) {
					// Non-indented line after Fields section, we're done
					break;
				}
			}
			
			if (shouldExportEnv && vaultEnvs.length > 0) {
				core.exportVariable(envManagedVariables, vaultEnvs.join(','));
			}
		}
		
		// If vault item is provided, don't process individual env vars
		return;
	}

	// Load secrets from environment variables using 1Password CLI.
	// Iterate over them to find 1Password references, extract the secret values,
	// and make them available in the next steps either as step outputs or as environment variables.
	const res = await exec.getExecOutput(`sh -c "op env ls"`);

	if (res.stdout === "") {
		return;
	}

	const envs = res.stdout.replace(/\n+$/g, "").split(/\r?\n/);
	for (const envName of envs) {
		extractSecret(envName, shouldExportEnv);
	}
	if (shouldExportEnv) {
		core.exportVariable(envManagedVariables, envs.join());
	}
};

export const unsetPrevious = (): void => {
	if (process.env[envManagedVariables]) {
		core.info("Unsetting previous values ...");
		const managedEnvs = process.env[envManagedVariables].split(",");
		for (const envName of managedEnvs) {
			core.info(`Unsetting ${envName}`);
			core.exportVariable(envName, "");
		}
	}
};
