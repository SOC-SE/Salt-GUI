/**
 * User Management Routes
 *
 * User listing, creation, disabling, and permission management on remote minions.
 * Supports both Linux and Windows systems.
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { resolveTargets } = require('../lib/targets');

// All routes require authentication
router.use(requireAuth);

/**
 * Helper: get kernel map for targets using cached batch resolution
 * Returns null and sends 404 if no minions respond.
 */
async function getKernelMap(targets, res) {
  const resolved = resolveTargets(targets);
  if (!resolved.valid) {
    res.status(400).json({ success: false, error: resolved.error });
    return null;
  }

  const kernels = await saltClient.getKernels(resolved.targets);
  if (!kernels || Object.keys(kernels).length === 0) {
    res.status(404).json({ success: false, error: 'No minions responded' });
    return null;
  }

  return kernels;
}

/**
 * Helper: get kernel + os_family for targets that need both
 */
async function getGrainsMap(targets, grainNames) {
  const resolved = resolveTargets(targets);
  if (!resolved.valid) return null;

  return saltClient.grainsItem(resolved.tgt, grainNames);
}

/**
 * GET /api/users/list
 * List users on target minion(s)
 */
router.post('/list', async (req, res) => {
  const { targets } = req.body;

  if (!targets) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: targets'
    });
  }

  try {
    const kernels = await getKernelMap(targets, res);
    if (!kernels) return;

    const results = {};

    // Process minions in parallel
    const minionPromises = Object.entries(kernels).map(async ([minion, kernel]) => {
      try {
        let users = [];

        if (kernel === 'Windows') {
          const cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: ['Get-LocalUser | Select-Object Name,Enabled,Description | ConvertTo-Json'],
            kwarg: { shell: 'powershell', timeout: 30 }
          });

          const output = cmdResult[minion];
          if (output?.retcode === 0 && output?.stdout) {
            try {
              const parsed = JSON.parse(output.stdout);
              const userList = Array.isArray(parsed) ? parsed : [parsed];
              users = userList.map(u => ({
                username: u.Name,
                enabled: u.Enabled,
                description: u.Description || '',
                shell: 'N/A',
                home: `C:\\Users\\${u.Name}`,
                uid: 'N/A',
                groups: []
              }));
            } catch (e) {
              const lines = output.stdout.split('\n').filter(l => l.trim());
              users = lines.slice(4).filter(l => !l.includes('---')).map(l => ({
                username: l.trim(),
                enabled: true,
                description: '',
                shell: 'N/A',
                home: '',
                uid: 'N/A',
                groups: []
              }));
            }
          }
        } else {
          // Linux: Fetch passwd, shadow, and groups in parallel
          const [passwdResult, shadowResult, groupsResult] = await Promise.all([
            saltClient.run({
              client: 'local',
              fun: 'cmd.run_all',
              tgt: minion,
              arg: ['cat /etc/passwd'],
              kwarg: { shell: '/bin/bash', timeout: 30 }
            }),
            saltClient.run({
              client: 'local',
              fun: 'cmd.run_all',
              tgt: minion,
              arg: ['cat /etc/shadow 2>/dev/null || echo "no-access"'],
              kwarg: { shell: '/bin/bash', timeout: 30 }
            }),
            saltClient.run({
              client: 'local',
              fun: 'cmd.run_all',
              tgt: minion,
              arg: ['cat /etc/group'],
              kwarg: { shell: '/bin/bash', timeout: 30 }
            })
          ]);

          const passwdOutput = passwdResult[minion];
          if (passwdOutput?.retcode === 0 && passwdOutput?.stdout) {
            const lines = passwdOutput.stdout.split('\n').filter(l => l.trim());

            // Parse shadow info
            const shadowMap = {};
            const shadowOutput = shadowResult[minion];
            if (shadowOutput?.retcode === 0 && shadowOutput?.stdout !== 'no-access') {
              shadowOutput.stdout.split('\n').forEach(line => {
                const parts = line.split(':');
                if (parts.length >= 2) {
                  const locked = parts[1].startsWith('!') || parts[1].startsWith('*') || parts[1] === '!!';
                  shadowMap[parts[0]] = { locked };
                }
              });
            }

            // Parse group memberships
            const groupMap = {};
            if (groupsResult[minion]?.retcode === 0) {
              groupsResult[minion].stdout.split('\n').forEach(line => {
                const parts = line.split(':');
                if (parts.length >= 4 && parts[3]) {
                  const groupName = parts[0];
                  const members = parts[3].split(',');
                  members.forEach(member => {
                    if (!groupMap[member]) groupMap[member] = [];
                    groupMap[member].push(groupName);
                  });
                }
              });
            }

            users = lines.map(line => {
              const parts = line.split(':');
              const username = parts[0];
              const uid = parseInt(parts[2], 10);
              const shell = parts[6] || '/bin/sh';
              const home = parts[5] || '';
              const description = parts[4] || '';

              const shadowInfo = shadowMap[username] || {};
              const nologinShells = ['/sbin/nologin', '/usr/sbin/nologin', '/bin/false', '/usr/bin/false'];
              const isDisabledShell = nologinShells.includes(shell);
              const isLocked = shadowInfo.locked || false;

              const userGroups = groupMap[username] || [];
              const hasSudo = userGroups.includes('wheel') || userGroups.includes('sudo');

              return {
                username,
                uid,
                shell,
                home,
                description,
                enabled: !isLocked && !isDisabledShell,
                locked: isLocked,
                disabledShell: isDisabledShell,
                groups: userGroups,
                hasSudo,
                isSystem: uid < 1000 && uid !== 0
              };
            });
          }
        }

        results[minion] = {
          success: true,
          kernel,
          users
        };
      } catch (err) {
        results[minion] = {
          success: false,
          error: err.message
        };
      }
    });

    await Promise.all(minionPromises);

    res.json({
      success: true,
      results
    });

  } catch (error) {
    logger.error('Failed to list users', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/users/create
 * Create a new user on target minion(s)
 */
router.post('/create', async (req, res) => {
  const { targets, username, password, createHome = true, shell = '/bin/bash', sudo = false } = req.body;

  if (!targets || !username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, username, password'
    });
  }

  if (!/^[a-z_][a-z0-9_-]*[$]?$/.test(username)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid username format. Must start with lowercase letter or underscore.'
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      success: false,
      error: 'Password must be at least 8 characters'
    });
  }

  try {
    logger.warn(`Creating user ${username}`, {
      user: req.username,
      targets,
      newUser: username,
      sudo
    });

    // Need os_family for sudo group detection, so use grainsItem
    const grains = await getGrainsMap(targets, ['kernel', 'os_family']);

    if (!grains || Object.keys(grains).length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No minions responded'
      });
    }

    // Populate kernel cache from the grains we just fetched
    const kernelData = {};
    for (const [m, g] of Object.entries(grains)) {
      kernelData[m] = { kernel: g?.kernel };
    }
    saltClient.populateKernelCache(kernelData);

    const results = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, minionGrains] of Object.entries(grains)) {
      const kernel = minionGrains?.kernel || 'Linux';
      const osFamily = minionGrains?.os_family || 'RedHat';

      try {
        let cmdResult;

        if (kernel === 'Windows') {
          const escapedPassword = password.replace(/"/g, '`"');
          const command = `net user "${username}" "${escapedPassword}" /add`;

          cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [command],
            kwarg: { shell: 'cmd', timeout: 30 }
          });

          if (sudo && cmdResult[minion]?.retcode === 0) {
            await saltClient.run({
              client: 'local',
              fun: 'cmd.run_all',
              tgt: minion,
              arg: [`net localgroup Administrators "${username}" /add`],
              kwarg: { shell: 'cmd', timeout: 30 }
            });
          }
        } else {
          const homeFlag = createHome ? '-m' : '';
          const shellFlag = shell ? `-s ${shell}` : '';
          const createCmd = `useradd ${homeFlag} ${shellFlag} ${username}`;

          cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [createCmd],
            kwarg: { shell: '/bin/bash', timeout: 30 }
          });

          if (cmdResult[minion]?.retcode === 0 || cmdResult[minion]?.stderr?.includes('already exists')) {
            const escapedPassword = password.replace(/'/g, "'\\''");
            await saltClient.run({
              client: 'local',
              fun: 'cmd.run_all',
              tgt: minion,
              arg: [`echo '${username}:${escapedPassword}' | chpasswd`],
              kwarg: { shell: '/bin/bash', timeout: 30 }
            });

            if (sudo) {
              const sudoGroup = osFamily === 'Debian' ? 'sudo' : 'wheel';
              await saltClient.run({
                client: 'local',
                fun: 'cmd.run_all',
                tgt: minion,
                arg: [`usermod -aG ${sudoGroup} ${username}`],
                kwarg: { shell: '/bin/bash', timeout: 30 }
              });
            }
          }
        }

        const minionResult = cmdResult[minion];
        if (minionResult?.retcode === 0) {
          results[minion] = {
            success: true,
            message: `User ${username} created successfully`
          };
          successCount++;
        } else {
          results[minion] = {
            success: false,
            error: minionResult?.stderr || minionResult?.stdout || 'Unknown error'
          };
          failCount++;
        }
      } catch (err) {
        results[minion] = {
          success: false,
          error: err.message
        };
        failCount++;
      }
    }

    res.json({
      success: failCount === 0,
      results,
      summary: {
        total: Object.keys(results).length,
        success: successCount,
        failed: failCount
      }
    });

  } catch (error) {
    logger.error('Failed to create user', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/users/disable
 * Disable a user account (lock and set nologin shell)
 * Does NOT delete the user - just prevents login
 */
router.post('/disable', async (req, res) => {
  const { targets, username } = req.body;

  if (!targets || !username) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, username'
    });
  }

  const protectedUsers = ['root', 'Administrator', 'SYSTEM'];
  if (protectedUsers.includes(username)) {
    return res.status(400).json({
      success: false,
      error: `Cannot disable protected user: ${username}`
    });
  }

  try {
    logger.warn(`Disabling user ${username}`, {
      user: req.username,
      targets,
      targetUser: username
    });

    const kernels = await getKernelMap(targets, res);
    if (!kernels) return;

    const results = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, kernel] of Object.entries(kernels)) {
      try {
        let cmdResult;

        if (kernel === 'Windows') {
          const command = `net user "${username}" /active:no`;
          cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [command],
            kwarg: { shell: 'cmd', timeout: 30 }
          });
        } else {
          // Linux: Lock account AND set shell to nologin
          // Run lock and shell change in parallel, expire sequentially
          const [lockResult] = await Promise.all([
            saltClient.run({
              client: 'local',
              fun: 'cmd.run_all',
              tgt: minion,
              arg: [`passwd -l ${username}`],
              kwarg: { timeout: 30 }
            }),
            saltClient.run({
              client: 'local',
              fun: 'cmd.run_all',
              tgt: minion,
              arg: [`usermod -s /sbin/nologin ${username}`],
              kwarg: { timeout: 30 }
            })
          ]);

          // Expire the account
          await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [`chage -E 0 ${username}`],
            kwarg: { timeout: 30 }
          });

          cmdResult = lockResult;
        }

        const minionResult = cmdResult[minion];
        if (minionResult?.retcode === 0) {
          results[minion] = {
            success: true,
            message: `User ${username} disabled (account locked, login shell changed to nologin)`
          };
          successCount++;
        } else {
          results[minion] = {
            success: false,
            error: minionResult?.stderr || minionResult?.stdout || 'Unknown error'
          };
          failCount++;
        }
      } catch (err) {
        results[minion] = {
          success: false,
          error: err.message
        };
        failCount++;
      }
    }

    res.json({
      success: failCount === 0,
      results,
      summary: {
        total: Object.keys(results).length,
        success: successCount,
        failed: failCount
      }
    });

  } catch (error) {
    logger.error('Failed to disable user', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/users/enable
 * Re-enable a disabled user account
 */
router.post('/enable', async (req, res) => {
  const { targets, username, shell = '/bin/bash' } = req.body;

  if (!targets || !username) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, username'
    });
  }

  try {
    logger.warn(`Enabling user ${username}`, {
      user: req.username,
      targets,
      targetUser: username
    });

    const kernels = await getKernelMap(targets, res);
    if (!kernels) return;

    const results = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, kernel] of Object.entries(kernels)) {
      try {
        let cmdResult;

        if (kernel === 'Windows') {
          const command = `net user "${username}" /active:yes`;
          cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [command],
            kwarg: { shell: 'cmd', timeout: 30 }
          });
        } else {
          // Check if password is set
          const checkResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [`getent shadow ${username} | cut -d: -f2`],
            kwarg: { shell: '/bin/bash', timeout: 30 }
          });

          const passwordField = checkResult[minion]?.stdout?.trim() || '';
          const hasNoPassword = passwordField === '*' || passwordField === '!!' || passwordField === '';

          if (hasNoPassword) {
            results[minion] = {
              success: false,
              error: `User ${username} has no password set (${passwordField}). Set a password first to enable login.`
            };
            failCount++;
            continue;
          }

          // Unlock and restore shell in parallel
          const [unlockResult] = await Promise.all([
            saltClient.run({
              client: 'local',
              fun: 'cmd.run_all',
              tgt: minion,
              arg: [`passwd -u ${username}`],
              kwarg: { timeout: 30 }
            }),
            saltClient.run({
              client: 'local',
              fun: 'cmd.run_all',
              tgt: minion,
              arg: [`usermod -s ${shell} ${username}`],
              kwarg: { timeout: 30 }
            }),
            saltClient.run({
              client: 'local',
              fun: 'cmd.run_all',
              tgt: minion,
              arg: [`chage -E -1 ${username}`],
              kwarg: { timeout: 30 }
            })
          ]);

          cmdResult = unlockResult;
        }

        const minionResult = cmdResult[minion];
        if (minionResult?.retcode === 0) {
          results[minion] = {
            success: true,
            message: `User ${username} enabled`
          };
          successCount++;
        } else {
          results[minion] = {
            success: false,
            error: minionResult?.stderr || minionResult?.stdout || 'Unknown error'
          };
          failCount++;
        }
      } catch (err) {
        results[minion] = {
          success: false,
          error: err.message
        };
        failCount++;
      }
    }

    res.json({
      success: failCount === 0,
      results,
      summary: {
        total: Object.keys(results).length,
        success: successCount,
        failed: failCount
      }
    });

  } catch (error) {
    logger.error('Failed to enable user', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/users/sudo
 * Add or remove sudo/admin access for a user
 */
router.post('/sudo', async (req, res) => {
  const { targets, username, grant = true } = req.body;

  if (!targets || !username) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, username'
    });
  }

  try {
    logger.warn(`${grant ? 'Granting' : 'Revoking'} sudo for user ${username}`, {
      user: req.username,
      targets,
      targetUser: username,
      action: grant ? 'grant' : 'revoke'
    });

    // Need os_family for sudo group detection
    const grains = await getGrainsMap(targets, ['kernel', 'os_family']);

    if (!grains || Object.keys(grains).length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No minions responded'
      });
    }

    // Populate kernel cache
    const kernelData = {};
    for (const [m, g] of Object.entries(grains)) {
      kernelData[m] = { kernel: g?.kernel };
    }
    saltClient.populateKernelCache(kernelData);

    const results = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, minionGrains] of Object.entries(grains)) {
      const kernel = minionGrains?.kernel || 'Linux';
      const osFamily = minionGrains?.os_family || 'RedHat';

      try {
        let cmdResult;

        if (kernel === 'Windows') {
          const action = grant ? '/add' : '/delete';
          const command = `net localgroup Administrators "${username}" ${action}`;
          cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [command],
            kwarg: { shell: 'cmd', timeout: 30 }
          });
        } else {
          const sudoGroup = osFamily === 'Debian' ? 'sudo' : 'wheel';

          let command;
          if (grant) {
            command = `usermod -aG ${sudoGroup} ${username}`;
          } else {
            command = `gpasswd -d ${username} ${sudoGroup}`;
          }

          cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [command],
            kwarg: { shell: '/bin/bash', timeout: 30 }
          });
        }

        const minionResult = cmdResult[minion];
        if (minionResult?.retcode === 0) {
          results[minion] = {
            success: true,
            message: `Sudo ${grant ? 'granted to' : 'revoked from'} ${username}`
          };
          successCount++;
        } else {
          results[minion] = {
            success: false,
            error: minionResult?.stderr || minionResult?.stdout || 'Unknown error'
          };
          failCount++;
        }
      } catch (err) {
        results[minion] = {
          success: false,
          error: err.message
        };
        failCount++;
      }
    }

    res.json({
      success: failCount === 0,
      results,
      summary: {
        total: Object.keys(results).length,
        success: successCount,
        failed: failCount
      }
    });

  } catch (error) {
    logger.error('Failed to modify sudo access', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/users/change-password
 * Change password for an existing user
 */
router.post('/change-password', async (req, res) => {
  const { targets, username, password } = req.body;

  if (!targets || !username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, username, password'
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      success: false,
      error: 'Password must be at least 8 characters'
    });
  }

  if (!/^[a-zA-Z0-9_\-\.]+$/.test(username)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid username format'
    });
  }

  try {
    logger.warn(`Changing password for user ${username}`, {
      user: req.username,
      targets,
      targetUser: username
    });

    const kernels = await getKernelMap(targets, res);
    if (!kernels) return;

    const results = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, kernel] of Object.entries(kernels)) {
      try {
        let cmdResult;

        if (kernel === 'Windows') {
          const command = `net user "${username}" "${password}"`;
          cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [command],
            kwarg: { shell: 'cmd', timeout: 30 }
          });
        } else {
          const escapedPassword = password.replace(/'/g, "'\\''");
          const command = `echo '${username}:${escapedPassword}' | chpasswd`;
          cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [command],
            kwarg: { shell: '/bin/bash', timeout: 30 }
          });
        }

        const minionResult = cmdResult[minion];
        if (minionResult?.retcode === 0) {
          results[minion] = {
            success: true,
            message: 'Password changed successfully'
          };
          successCount++;
        } else {
          results[minion] = {
            success: false,
            error: minionResult?.stderr || minionResult?.stdout || 'Unknown error'
          };
          failCount++;
        }
      } catch (err) {
        results[minion] = {
          success: false,
          error: err.message
        };
        failCount++;
      }
    }

    res.json({
      success: failCount === 0,
      results,
      summary: {
        total: Object.keys(results).length,
        success: successCount,
        failed: failCount
      }
    });

  } catch (error) {
    logger.error('Failed to change password', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
