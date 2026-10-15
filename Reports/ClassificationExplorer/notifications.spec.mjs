import { expect, test } from '@playwright/test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const explorerUrl = pathToFileURL(fileURLToPath(new URL('index.html', import.meta.url))).href;

async function openNotifications(page, kind, entry) {
    await page.addInitScript(({ kind, entry }) => {
        localStorage.removeItem('entraops.notifications.read.ClassificationExplorer');
        Object.defineProperty(window, 'EOCE_NOTIFICATION_DATA', {
            value: {
                notification: { changeSetId: 'notification-regression', sourceKeys: ['EntraID'] },
                sources: {
                    EntraID: {
                        label: 'Test catalog', kind,
                        commits: [{ date: '2026-10-15', added: [], removed: [], changed: [entry] }]
                    }
                }
            },
            writable: false
        });
    }, { kind, entry });
    await page.goto(explorerUrl);
    await page.locator('#notificationButton').click();
    return page.locator('.eo-notification-panel');
}

test('keeps a tier change separate from simultaneous role action changes', async ({ page }) => {
    const panel = await openNotifications(page, 'roles', {
        id: 'test-role', name: 'Test role', oldTier: 'UserAccess', newTier: 'ControlPlane',
        actionsAdded: ['microsoft.directory/test/read'], actionsRemoved: []
    });

    const definitions = panel.locator('.eo-notification-section').filter({ hasText: 'Microsoft role definitions' });
    await expect(definitions.locator('.eo-notification-item')).toHaveCount(1);
    await expect(definitions).toContainText('microsoft.directory/test/read');
    const model = panel.locator('.eo-notification-section').filter({ hasText: 'Classification model' });
    await expect(model).toContainText('Test role');
    await expect(model).toContainText('UserAccess -> ControlPlane');
    await expect(panel).not.toContainText('after role action changes');
});

for (const tierChanged of [false, true]) {
    test(`labels a permission category change with${tierChanged ? '' : 'out'} a tier change`, async ({ page }) => {
        const panel = await openNotifications(page, 'permissions', {
            id: 'test-permission', name: 'Test.Read.All', oldTier: 'UserAccess',
            newTier: tierChanged ? 'ControlPlane' : 'UserAccess',
            oldCategory: 'Old category', newCategory: 'New category'
        });

        await expect(panel.locator('.eo-notification-group-title')).toContainText(
            tierChanged ? 'Tier and category changed' : 'Category changed'
        );
        await expect(panel).toContainText('Category: Old category -> New category');
        if (!tierChanged) await expect(panel).not.toContainText('Tier assignment changed');
    });
}
