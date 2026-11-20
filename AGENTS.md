# Working on PatchRocket

## Make configuration available in Settings

Expose every supported configurable option in the dashboard under **Settings**. When adding or changing an integration, credential, schedule, approval rule, or other setting, include its dashboard controls in the same change. Operators should be able to configure PatchRocket through the dashboard without editing files, setting environment variables, or running console commands. These mechanisms can support initial installation and automation.

## Keep remediation owned by PatchRocket

PatchRocket is responsible for delivering remediation through its own workflows. When a remediation gets stuck, diagnose the failure and fix the underlying code, configuration, integration, or workflow. Retry or resume through PatchRocket so it produces the patch, runs the checks, and records the outcome. Use the configured approval and rollout workflow, and require observed runtime evidence before marking a deployment verified. A manual fix outside PatchRocket does not count as a completed PatchRocket remediation.

## Fit the customer's infrastructure

Design for customers ranging from a small shop that ships ZIP archives over FTP or SSH to an enterprise operating fleets across many clusters and data centres. Treat specific vendors, platforms, tools, and deployment models as integration choices. Support widely used software development lifecycle and patching practices where practical, and keep each integration's prerequisites specific to that integration. Customers should be able to adopt PatchRocket within their existing source control, build, approval, and deployment workflows.
