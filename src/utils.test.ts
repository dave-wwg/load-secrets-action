import * as core from "@actions/core";
import * as exec from "@actions/exec";
import { read, setClientInfo } from "@1password/op-js";
import {
	extractSecret,
	loadSecrets,
	unsetPrevious,
	validateAuth,
} from "./utils";
import {
	authErr,
	envConnectHost,
	envConnectToken,
	envManagedVariables,
	envServiceAccountToken,
	envVaultItem,
} from "./constants";

jest.mock("@actions/core");
jest.mock("@actions/exec", () => ({
	getExecOutput: jest.fn(() => ({
		stdout: "MOCK_SECRET",
	})),
}));
jest.mock("@1password/op-js");

beforeEach(() => {
	jest.clearAllMocks();
});

describe("validateAuth", () => {
	const testConnectHost = "https://localhost:8000";
	const testConnectToken = "token";
	const testServiceAccountToken = "ops_token";

	beforeEach(() => {
		process.env[envConnectHost] = "";
		process.env[envConnectToken] = "";
		process.env[envServiceAccountToken] = "";
	});

	it("should throw an error when no config is provided", () => {
		expect(validateAuth).toThrow(authErr);
	});

	it("should throw an error when partial Connect config is provided", () => {
		process.env[envConnectHost] = testConnectHost;
		expect(validateAuth).toThrow(authErr);
	});

	it("should be authenticated as a Connect client", () => {
		process.env[envConnectHost] = testConnectHost;
		process.env[envConnectToken] = testConnectToken;
		expect(validateAuth).not.toThrow(authErr);
		expect(core.info).toHaveBeenCalledWith("Authenticated with Connect.");
	});

	it("should be authenticated as a service account", () => {
		process.env[envServiceAccountToken] = testServiceAccountToken;
		expect(validateAuth).not.toThrow(authErr);
		expect(core.info).toHaveBeenCalledWith(
			"Authenticated with Service account.",
		);
	});

	it("should prioritize Connect over service account if both are configured", () => {
		process.env[envServiceAccountToken] = testServiceAccountToken;
		process.env[envConnectHost] = testConnectHost;
		process.env[envConnectToken] = testConnectToken;
		expect(validateAuth).not.toThrow(authErr);
		expect(core.warning).toHaveBeenCalled();
		expect(core.info).toHaveBeenCalledWith("Authenticated with Connect.");
	});
});

describe("extractSecret", () => {
	const envTestSecretEnv = "TEST_SECRET";
	const testSecretRef = "op://vault/item/secret";
	const testSecretValue = "Secret1@3$";

	read.parse = jest.fn().mockReturnValue(testSecretValue);

	process.env[envTestSecretEnv] = testSecretRef;

	it("should set secret as step output", () => {
		extractSecret(envTestSecretEnv, false);
		expect(core.exportVariable).not.toHaveBeenCalledWith(
			envTestSecretEnv,
			testSecretValue,
		);
		expect(core.setOutput).toHaveBeenCalledWith(
			envTestSecretEnv,
			testSecretValue,
		);
		expect(core.setSecret).toHaveBeenCalledWith(testSecretValue);
	});

	it("should set secret as environment variable", () => {
		extractSecret(envTestSecretEnv, true);
		expect(core.exportVariable).toHaveBeenCalledWith(
			envTestSecretEnv,
			testSecretValue,
		);
		expect(core.setOutput).not.toHaveBeenCalledWith(
			envTestSecretEnv,
			testSecretValue,
		);
		expect(core.setSecret).toHaveBeenCalledWith(testSecretValue);
	});
});

describe("loadSecrets", () => {
	it("sets the client info and gets the executed output", async () => {
		await loadSecrets(true);

		expect(setClientInfo).toHaveBeenCalledWith({
			name: "1Password GitHub Action",
			id: "GHA",
		});
		expect(exec.getExecOutput).toHaveBeenCalledWith('sh -c "op env ls"');
		expect(core.exportVariable).toHaveBeenCalledWith(
			"OP_MANAGED_VARIABLES",
			"MOCK_SECRET",
		);
	});

	it("return early if no env vars with secrets found", async () => {
		(exec.getExecOutput as jest.Mock).mockReturnValueOnce({ stdout: "" });
		await loadSecrets(true);

		expect(exec.getExecOutput).toHaveBeenCalledWith('sh -c "op env ls"');
		expect(core.exportVariable).not.toHaveBeenCalled();
	});

	describe("core.exportVariable", () => {
		it("is called when shouldExportEnv is true", async () => {
			await loadSecrets(true);

			expect(core.exportVariable).toHaveBeenCalledTimes(1);
		});

		it("is not called when shouldExportEnv is false", async () => {
			await loadSecrets(false);

			expect(core.exportVariable).not.toHaveBeenCalled();
		});
	});

	describe('with OP_VAULT_ITEM_OPTION', () => {
		const mockVaultItemOutput = `
ID:          some_vault_item_id
Title:       some_item
Vault:       some_vault (some_vault_id)
Created:     1 day ago
Updated:     1 hour ago by Dave @ WhereWeGo
Favorite:    false
Version:     2
Category:    SECURE_NOTE
Fields:
  notesPlain:                            a skippable note
  SECRET_1:                              some secret
  SECRET_2:                              abc123
`;

		beforeEach(() => {
			(exec.getExecOutput as jest.Mock).mockClear();
		});

		afterEach(() => {
			delete process.env[envVaultItem];
		});

		it('throws error for invalid vault item format', async () => {
			process.env[envVaultItem] = "invalid-format";
			
			await expect(loadSecrets(true)).rejects.toThrow('Invalid vault item format: invalid-format');
		});

		it('throws error for vault item format targeting an individual field', async () => {
			process.env[envVaultItem] = "op://vault/item/some_item";
			
			await expect(loadSecrets(true)).rejects.toThrow('Invalid vault item format: op://vault/item/some_item');
		});

		it('fetches all secrets from the vault item and exports as environment variables', async () => {
			process.env[envVaultItem] = "op://vault/some_item";
			(exec.getExecOutput as jest.Mock).mockResolvedValueOnce({
				stdout: mockVaultItemOutput
			});

			await loadSecrets(true);

			expect(exec.getExecOutput).toHaveBeenCalledWith('sh -c "op item get op://vault/some_item --reveal"');
			expect(core.exportVariable).toHaveBeenCalledWith('SECRET_1', 'some secret');
			expect(core.exportVariable).toHaveBeenCalledWith('SECRET_2', 'abc123');
			expect(core.exportVariable).toHaveBeenCalledWith(envManagedVariables, 'SECRET_1,SECRET_2');
			expect(core.setSecret).toHaveBeenCalledWith('some secret');
			expect(core.setSecret).toHaveBeenCalledWith('abc123');
		});

		it('fetches all secrets from the vault item and sets as step outputs', async () => {
			process.env[envVaultItem] = "op://vault/some_item";
			(exec.getExecOutput as jest.Mock).mockResolvedValueOnce({
				stdout: mockVaultItemOutput
			});

			await loadSecrets(false);

			expect(exec.getExecOutput).toHaveBeenCalledWith('sh -c "op item get op://vault/some_item --reveal"');
			expect(core.setOutput).toHaveBeenCalledWith('SECRET_1', 'some secret');
			expect(core.setOutput).toHaveBeenCalledWith('SECRET_2', 'abc123');
			expect(core.exportVariable).not.toHaveBeenCalledWith(envManagedVariables, expect.any(String));
			expect(core.setSecret).toHaveBeenCalledWith('some secret');
			expect(core.setSecret).toHaveBeenCalledWith('abc123');
		});

		it('skips notesPlain field', async () => {
			process.env[envVaultItem] = "op://vault/some_item";
			(exec.getExecOutput as jest.Mock).mockResolvedValueOnce({
				stdout: mockVaultItemOutput
			});

			await loadSecrets(true);

			expect(core.exportVariable).not.toHaveBeenCalledWith('notesPlain', expect.any(String));
			expect(core.setOutput).not.toHaveBeenCalledWith('notesPlain', expect.any(String));
			expect(core.setSecret).not.toHaveBeenCalledWith('will be loaded in "deploy-preview.yml" GH Action');
		});

		it('returns early and does not process individual env vars when vault item is provided', async () => {
			process.env[envVaultItem] = "op://vault/some_item";
			(exec.getExecOutput as jest.Mock).mockResolvedValueOnce({
				stdout: mockVaultItemOutput
			});

			await loadSecrets(true);

			// Should only call exec.getExecOutput once for the vault item, not for "op env ls"
			expect(exec.getExecOutput).toHaveBeenCalledTimes(1);
			expect(exec.getExecOutput).toHaveBeenCalledWith('sh -c "op item get op://vault/some_item --reveal"');
			expect(exec.getExecOutput).not.toHaveBeenCalledWith('sh -c "op env ls"');
		});

		it('handles empty vault item output gracefully', async () => {
			process.env[envVaultItem] = "op://vault/some_item";
			(exec.getExecOutput as jest.Mock).mockResolvedValueOnce({
				stdout: ""
			});

			await loadSecrets(true);

			expect(exec.getExecOutput).toHaveBeenCalledWith('sh -c "op item get op://vault/some_item --reveal"');
			expect(core.exportVariable).not.toHaveBeenCalledWith(envManagedVariables, expect.any(String));
		});
	})
});

describe("unsetPrevious", () => {
	const testManagedEnv = "TEST_SECRET";
	const testSecretValue = "MyS3cr#T";

	beforeEach(() => {
		process.env[testManagedEnv] = testSecretValue;
		process.env[envManagedVariables] = testManagedEnv;
	});

	it("should unset the environment variable if user wants it", () => {
		unsetPrevious();
		expect(core.info).toHaveBeenCalledWith("Unsetting previous values ...");
		expect(core.info).toHaveBeenCalledWith("Unsetting TEST_SECRET");
		expect(core.exportVariable).toHaveBeenCalledWith("TEST_SECRET", "");
	});
});
