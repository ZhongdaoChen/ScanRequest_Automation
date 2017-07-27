import Getter_And_Setter

def comfirm_in_DMZ(conn):

    # There are the site_id of the following sites, this is a manually process currently.:
    # More Like DMZ VLAN 151, 1sum-dmz-ext VLAN 112, Internal DMZ VLAN 248, TCGA DMZ Network VLAN 127,
    # Hadoop cluster DMZ VLAN 152, Aspera DMZ Network VLAN 2023, Nervepoint-DMZ VLAN 253,
    # Ext-Server DMZ (Private VLAN) VLAN 150/850/950
    print("Trying to confirm if this host is in DMZ...")
    dmz_site_info = {'38':'DMZ VLAN 151',
                     '168':'1sum-dmz-ext VLAN 112',
                     '53':'Internal DMZ VLAN 248',
                     '42':'TCGA DMZ Network VLAN 127',
                     '39':'Hadoop cluster DMZ VLAN 152',
                     '43':'Aspera DMZ Network VLAN 2023',
                     '182':'Nervepoint-DMZ VLAN 253',
                     '40':'Ext-Server DMZ (Private VLAN) VLAN 150/850/950]'}
    cur = conn.cursor()
    temp_asset_id = Getter_And_Setter.get_host_assetID()
    sql = 'SELECT site_id from "public"."dim_site_asset" WHERE asset_id =' + "'" + temp_asset_id + "'"

    cur.execute(sql)
    rows = cur.fetchall()


    for row in rows:
         if str(row)[1:-2] in dmz_site_info.keys():
             Getter_And_Setter.set_host_siteID(str(row)[1:-2])
             print "This host belongs to DMZ: {0}\n".format(dmz_site_info[str(row)[1:-2]])
             return True
         else:
             continue

    print("This host doesn't belong to and DMZ. Please contact Infosec to launch a scan")
    exit("Not in DMZ")
