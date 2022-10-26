#reads adfs service settings directly from ADFSConfigurationDB
#and returns the data as XML to caller functions
#the user needs to be localAdmin for WID
#the user running the script needs to have permissions to logon/access the DB on SQL Servers or would fail otherwise
function get-servicesettingsfromdb ()
{
    $stsWMIObject = (Get-WmiObject -Namespace root\ADFS -Class SecurityTokenService)
    #Create SQL Connection
    $connection = new-object system.data.SqlClient.SqlConnection($stsWMIObject.ConfigurationDatabaseConnectionString);
    $connection.Open()

    $query = "SELECT * FROM IdentityServerPolicy.ServiceSettings"  
    $sqlcmd = $connection.CreateCommand();
    $sqlcmd.CommandText = $query;
    $result = $sqlcmd.ExecuteReader();
    $table = new-object "System.Data.DataTable"
    $table.Load($result)
    [XML]$SSD=  $table.ServiceSettingsData
    return $SSD

}
