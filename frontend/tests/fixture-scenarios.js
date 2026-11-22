const releaseTrackingPath = '/remediations/' + '9'.repeat(24) + '#release-tracking';

export const fixtureScenarios = {
    default: {
        description: 'Mixed inventory, findings, and Queue activity.',
        startPath: '/',
    },
    empty: {
        description: 'Accounts are ready and inventory is empty.',
        startPath: '/',
    },
    'first-admin': {
        description: 'A one-time code for claiming the first administrator.',
        startPath: '/setup',
    },
    'first-discovery-failure': {
        description: 'A failed source discovery before any assets have been recorded.',
        startPath: '/',
    },
    'docker-scan-handoff': {
        description: 'Completed Docker discovery with an unscanned image and an empty host.',
        startPath: '/settings/getting-started?discovery_result=complete#getting-started-discovery',
    },
    'many-connections': {
        description: 'Multiple pages of infrastructure, repository, and cluster connections.',
        startPath: '/settings/connections#infrastructure-connections',
    },
    'many-users': {
        description: 'Multiple pages of local accounts.',
        startPath: '/app/users#local-users',
    },
    'delivery-discovery': {
        description: 'Delivery services and candidates across several sources.',
        startPath: '/settings/discovery#discovered-candidates',
    },
    'registry-cleanup-history': {
        description: 'Five pages of registry cleanup requests with an older request awaiting review.',
        startPath: '/settings/registry-cleanup?cleanup_page=4#cleanup-requests',
    },
    'vm-package-history': {
        description: 'A verified package update at the end of a full host history page.',
        startPath: '/app/queue?vm_state=closed#vm-package-jobs',
    },
    'queue-transports': {
        description: 'Ready work with a recent heartbeat and an expired claim on a separate transport.',
        startPath: '/app/queue#transports',
    },
    executables: {
        description: 'Installed executables across two pages, including one with recorded scan evidence.',
        startPath: '/binaries?q=logshipper#executable-results',
    },
    'executable-builds': {
        description: 'An installed test executable with a fixing commit and approved build attempts.',
        startPath: '/binaries?q=fixture-runner#executable-results',
    },
    'finding-targets': {
        description: 'The same advisory and package recorded from several lockfiles, including a past detection.',
        startPath: '/findings?advisory=PP-TARGET-FIXTURE&observation=all#vulnerability-results',
    },
    'finding-sources': {
        description: 'An image finding linked to a build repository, a deployment, and a matching source finding.',
        startPath: '/findings?advisory=PP-PREPARE-FIXTURE&asset_name=patch+target#vulnerability-results',
    },
    'finding-runtime': {
        description: 'A scanned image digest running across inventory records and container pages.',
        startPath: '/findings?advisory=PP-RUNTIME-FIXTURE#vulnerability-results',
    },
    'finding-pages': {
        description: 'Three pages of findings and advisory groups for one package.',
        startPath: '/findings?view=advisories&package=fixture%2Fpreview#vulnerability-results',
    },
    'finding-history': {
        description: 'A finding with a searchable remediation history spanning three pages.',
        startPath: '/findings?advisory=PP-RETRY-FIXTURE#vulnerability-results',
    },
    'remediation-timeline': {
        description: 'A remediation with an execution history that spans multiple pages.',
        startPath: '/remediations/' + 'a'.repeat(24) + '#execution-timeline',
    },
    'pull-request-connection': {
        description: 'A recorded pull request with a repository connection whose canonical URL needs correction.',
        startPath: '/remediations/' + 'e'.repeat(24) + '#pull-request',
    },
    'docker-rollout': {
        description: 'Staged and verified Docker canaries.',
        startPath: '/settings/policy#rollout-schedules',
    },
    'release-queue': {
        description: 'Release trackers in multiple polling states.',
        startPath: '/app/queue?release_state=blocked#release-trackers',
    },
    'release-registry': {
        description: 'Release evidence for registry authentication.',
        startPath: releaseTrackingPath,
    },
    'release-delivery': {
        description: 'Release evidence linked to delivery infrastructure.',
        startPath: releaseTrackingPath,
    },
    'release-rollout': {
        description: 'Release evidence linked to rollout verification.',
        startPath: releaseTrackingPath,
    },
};
