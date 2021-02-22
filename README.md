# LAAMB (LogicAppAbuserMakesBackdoors)
Creates backdoor user account by abusing logic app contributor permissions and azuread api connections


[![asciicast](https://asciinema.org/a/392924.svg)](https://asciinema.org/a/392924)

## What does this do

```
Replaces source code of existing logic app with an app that creates a user account and assigns it to a security group
Once the malicious app is finished running. The original app source code is reverted back to normal.

It does this by abusing the logic app contributor role and the azuread api connection
First it enumerates logic apps, logic app api connections and AzureAd security groups with privileges we want.
Api connections can be used interchangebly by different logic apps regardless of the resource group
The only requirement is they must be in the same location (Example eastus)

So once an azuread api connection is found we can then use that connection within a completely different logic app 
And take advantage of the azuread privileges assigned to that connector and replace the source code of the logic app with a new logic app
That creates a new user and adds them to a group with privileges we want to have using that azuread api connector.

The catch is that logic app contributor is required on an azuread api connection AND a logic app.
This is usually the case as engineers working with logic apps create them in a resource group while working on the logic app.
Usually the azuread api connection is authenticated by a global admin or security admin in azureAD. But the person who has the actual permissions to the connection itself is the engineer.

So the idea is that, there are alot of api connections just laying around that maybe are not even attached to logic apps, and perhaps some of them are the azuread api connection.
And you have logic app contributor (or contributor) on alot of resource groups (or subscription wide lol). But you have no azuread permissions.
Well now you do! this is useful for privesc or just creating a backdoor user.
```

## Usage
Use Connect-AzAccount or authenticate some other way then try one of the below command

```
Import-Module .\LAAMB.ps1
```

```
-subscriptionId required
-resourceGroup only searches for logic apps and connections in that resourceGroup (Default:All)
-desiredPriv looks for security groups with that role assigned at any scope (Default:Contributor)
-username username for backdoor account (Default:AzureSupport
-password password for backdoor account (Default:turtleshell123!!!)
-domain @whatever for tenant targeted (Default:Tries to get it automatically may fail)
```

```
Execute-LAAMB -subscriptionId "00000-1000-0000--000-1b00000000" -desiredPriv "Owner"
```

```
Execute-LAAMB -subscriptionId "00000-1000-0000--000-1b00000000" -resourceGroup "specific RG" -desiredPriv "Contributor" -username "gotim" -password "pwned"
```

```
Execute-LAAMB -subscriptionId "00000-1000-0000--000-1b00000000" -resourceGroup "all"
```

```
Execute-LAAMB -subscriptionId "00000-1000-0000--000-1b00000000" -domain mycompany.com
```

## Requirements needed for this to work
* an azuread api connection must already exist somewhere in the same region as the logic app being targeted (but doesnt have to be in same resource group) <--- Important
* logic app contributor is needed on both the targeted logic app and the api connection <--- Important
* Microsoft.Authorization/*/read access to subscription (ideally via Reader Role) OR to specific resource groups to be able to enumerate role assignments and check if it matches desired privs <--- Important

## Things to keep in mind
* If you have logic app contributor access to another azuread api connection in another resource group but its in the same location (ex Eastus) as the logic app target you can abuse it.
* So if theres many api connections that are not cleaned up and you have subscription wide logic app contributor your chances of success are high as you will be able to enumerate all security group assigned roles and view and manage all api connections and logic apps.
* If there are no azuread api connections this will not work since that is needed to create user and add to group.


## Situations you should definitely try this out
* You have logic app contributor on a resource group + any other role subscription wide
* You have logic app contributor subscription wide

## Summary

```
If you happen to get access to an account that has reader (or any other role that has Microsoft.Authorization/*/read) on alot of resource groups (or whole subscription) and have logic app contributor on a resource group (or subscription wide)
You can potentially elevate your privileges if there is an azuread api connection in that same location that you also have logic app contributor access too.
```

## To do (That i will never do)
* Finish -Goverment switch
