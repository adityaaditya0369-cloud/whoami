# Northwind application architecture notes (FICTIONAL sample)

These notes are sample content for the IdentityBridge AI demo. They are not about a real company.

## Portal and reporting
The Employee Portal calls the Reporting API to show the sales and finance dashboards on the home page.
Access tokens for the Reporting API are issued by the Northwind API authorization server.

## Finance
Mobile Expenses depends on the Expense Portal for receipts and approvals; both are used by the Finance team.
The Expense Portal (UAT) environment is refreshed from production every quarter.

## Service management
ServiceNow integrates with Salesforce to sync customer cases every hour.
