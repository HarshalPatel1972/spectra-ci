import express from 'express';
import { Webhooks } from '@octokit/webhooks';
import { Octokit } from '@octokit/rest';
import * as dotenv from 'dotenv';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

dotenv.config();

const execAsync = promisify(exec);

const app = express();
const port = process.env.PORT || 3000;

const webhooks = new Webhooks({
    secret: process.env.GITHUB_WEBHOOK_SECRET || 'development_secret',
});

const octokit = new Octokit({
    auth: process.env.GITHUB_TOKEN
});

// Middleware to parse GitHub webhook payloads
app.use(express.json());

app.post('/api/webhook', async (req, res) => {
    try {
        await webhooks.verifyAndReceive({
            id: req.headers['x-github-delivery'] as string,
            name: req.headers['x-github-event'] as any,
            payload: req.body,
            signature: req.headers['x-hub-signature-256'] as string,
        });
        res.status(200).send('Webhook received');
    } catch (error) {
        console.error('Webhook verification failed', error);
        res.status(400).send('Webhook verification failed');
    }
});

webhooks.on('pull_request.opened', handlePullRequest);
webhooks.on('pull_request.synchronize', handlePullRequest);

async function handlePullRequest({ payload }: any) {
    const owner = payload.repository.owner.login;
    const repo = payload.repository.name;
    const pull_number = payload.pull_request.number;
    const headSha = payload.pull_request.head.sha;

    console.log(`Processing PR #${pull_number} for ${owner}/${repo}`);

    // 1. Fetch changed files
    const { data: files } = await octokit.pulls.listFiles({
        owner,
        repo,
        pull_number,
    });

    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), `spectra-ci-${pull_number}-`));

    try {
        // 2. Download and save changed files to temp directory
        for (const file of files) {
            if (file.status === 'removed') continue;
            
            // Get file content from the PR head
            const { data: fileContent } = await octokit.repos.getContent({
                owner,
                repo,
                path: file.filename,
                ref: headSha,
            }) as any;

            if (fileContent.type === 'file' && fileContent.content) {
                const buffer = Buffer.from(fileContent.content, 'base64');
                const filePath = path.join(tempDir, file.filename);
                
                await fs.mkdir(path.dirname(filePath), { recursive: true });
                await fs.writeFile(filePath, buffer);
            }
        }

        // 3. Run Spectra scan on the temp directory
        let findings: any[] = [];
        let aggregateQrs = 0;
        
        try {
            const { stdout } = await execAsync(`chmod +x ./spectra-linux-amd64 && ./spectra-linux-amd64 scan "${tempDir}" --output json --quiet`);
            const result = JSON.parse(stdout);
            findings = result.findings || [];
            aggregateQrs = result.aggregate_qrs || 0;
        } catch (error: any) {
            if (error.stdout) {
                try {
                    const result = JSON.parse(error.stdout);
                    findings = result.findings || [];
                    aggregateQrs = result.aggregate_qrs || 0;
                } catch(e) {}
            }
        }

        // 4. Post comment if findings exist
        if (findings.length > 0) {
            await postPRComment(owner, repo, pull_number, headSha, findings, aggregateQrs);
        } else {
            // Optional: Post a success comment or just do nothing
            console.log('No cryptographic debt found. PR is clean.');
        }

    } catch (error) {
        console.error('Error processing PR:', error);
    } finally {
        // Cleanup temp directory
        await fs.rm(tempDir, { recursive: true, force: true });
    }
}

async function postPRComment(owner: string, repo: string, pull_number: number, commit_id: string, findings: any[], aggregateQrs: number) {
    let markdown = `## 🛡️ Spectra Cryptographic Security Scan\n\n`;
    markdown += `**Aggregate Quantum Risk Score (QRS):** ${aggregateQrs}/100\n\n`;
    
    if (aggregateQrs >= 80) {
        markdown += `> [!CAUTION]\n> **CRITICAL RISK DETECTED.** This PR introduces cryptography that is immediately vulnerable to harvest-now-decrypt-later attacks.\n\n`;
    } else if (aggregateQrs >= 60) {
        markdown += `> [!WARNING]\n> **HIGH RISK DETECTED.** This PR introduces legacy cryptography. Migration to PQC is highly recommended.\n\n`;
    }

    markdown += `### Findings\n\n`;
    markdown += `| File | Algorithm | QRS | Risk | Migration Effort |\n`;
    markdown += `|---|---|---|---|---|\n`;

    for (const f of findings) {
        // Strip tempDir path from file_path
        const relativePath = f.file_path.split(path.sep).slice(1).join('/');
        markdown += `| \`${relativePath}:${f.line_number}\` | **${f.algorithm}** | ${f.qrs} | ${f.risk_band} | ${f.migration_effort} |\n`;
    }

    markdown += `\n---\n*Scanned automatically by [Spectra CI](https://spectra.tools)*`;

    await octokit.issues.createComment({
        owner,
        repo,
        issue_number: pull_number,
        body: markdown
    });
}

app.listen(port, () => {
    console.log(`Spectra CI webhook server listening on port ${port}`);
});
