<?php
/*
Plugin Name: Sucuri Security
Plugin URI: http://wordpress.sucuri.net/
Description: WordPress Audit log and integrity checking plugin. Developed by Sucuri Security, this plugin will monitor your Wordpress installation for the latest attacks and provide visibility to what is happening inside (auditing). It will also keep track of system events, like logins, logouts, failed logins, new users, file changes, etc. When an attack is detected it will also block the IP address from accessing the site. 
Author: http://sucuri.net
Version: 2.0
Author URI: http://sucuri.net
*/


/* Sucuri Security WordPress Plugin
 * Copyright (C) 2010-2012 Sucuri Security - http://sucuri.net
 * Released under the GPL - see LICENSE file for details.
 */


/* No direct access. */
if(!function_exists('add_action'))
{
    exit(0);
}


/* Constants. */
define("SUCURIWPSTARTED", TRUE);
define('SUCURI','sucurisec' );
define('SUCURI_VERSION','2.0');
define('SUCURI_DEBUG', TRUE);
define('SUCURI_IMG',plugin_dir_url( __FILE__ ).'images/' );



/* Debug log. */
function sucuri_debug_log($msg)
{
    if(!is_file(ABSPATH."/wp-content/uploads/sucuri/debug_log.php"))
    {
        @file_put_contents(ABSPATH."/wp-content/uploads/sucuri/debug_log.php", "<?php exit(0);\n");
    }
    @file_put_contents(ABSPATH."/wp-content/uploads/sucuri/debug_log.php", date('Y-m-d h:i:s ')."$msg\n", FILE_APPEND);
}



/* Starting Sucuri side bar. */
function sucuri_menu() 
{
    add_menu_page('Sucuri Security', 'Sucuri Security', 'manage_options', 
                  'sucurisec', 'sucuri_admin_page', SUCURI_IMG.'menu-icon.png');

    add_submenu_page('sucurisec', 'Dashboard', 'Dashboard', 'manage_options',
                     'sucurisec', 'sucuri_admin_page');

    add_submenu_page('sucurisec', 'Settings', 'Settings', 'manage_options',
                     'sucurisec_settings', 'sucuri_settings_page');

    add_submenu_page('sucurisec', 'Malware Scanning', 'Malware Scanning', 
                     'manage_options',
                     'sucurisec_malwarescan', 'sucuri_malwarescan_page');

    add_submenu_page('sucurisec', '1-Click Hardening', '1-Click Hardening', 
                     'manage_options',
                     'sucurisec_hardening', 'sucuri_hardening_page');
}



/* Modifying API key. */
function sucuri_modify_values()
{
    sucuri_activate_scan();
    if(!is_dir(ABSPATH."/wp-content/uploads/sucuri/blocks"))
    {
        return("ERROR: Unable to activate. Without permissions to modify ".ABSPATH."/wp-content/uploads/sucuri/blocks");
    }
    if(!is_file(ABSPATH."/wp-content/uploads/sucuri/blocks/blocks.php"))
    {
        return("ERROR: Unable to activate. Without permissions to modify ".ABSPATH."/wp-content/uploads/sucuri/");
    }

    if(isset($_SERVER['SUCURI_RIP']))
    {
        @touch(ABSPATH."/wp-content/uploads/sucuri/whitelist/".$_SERVER['SUCURI_RIP']);
    }
    @touch(ABSPATH."/wp-content/uploads/sucuri/whitelist/".$_SERVER["REMOTE_ADDR"]);
    @touch(ABSPATH."/wp-content/uploads/sucuri/whitelist/".$_SERVER['SERVER_ADDR']);

    if(isset($_POST['wpsucuri-newkey']))
    {
        $newkey = htmlspecialchars(trim($_POST['wpsucuri-newkey']));
        if(preg_match("/^[a-zA-Z0-9]+$/", $newkey, $regs, PREG_OFFSET_CAPTURE,0))
        {
            $res = sucuri_send_log($newkey, "INFO: Authentication key added and plugin enabled.");
            if($res == 1)
            {
                update_option('sucuri_wp_key', $newkey);

                sucuri_debug_log("Activating key $newkey..");
                if(!wp_next_scheduled( 'sucuri_hourly_scan')) 
                {
                    sucuri_debug_log("Activating wp_schedule event..");
	            wp_schedule_event(time() + 10, 'hourly', 'sucuri_hourly_scan');
                }

                sucuri_debug_log("Scheduling next single event..");
                wp_schedule_single_event(time()+300, 'sucuri_hourly_scan');
                return(NULL);
            }
            else if($res == -1)
            {
                return("ERROR: Unable to connect to https://wordpress.sucuri.net (check for curl + SSL support on PHP).");
            }
            else
            {
                return("ERROR: Key invalid. Not accepted by sucuri.net.");
            }
        }
        else
        {
            return("ERROR: Invalid key.");
        }
    }


    /* Enabling or disabling remediation. */
    if(isset($_POST['sucuri_re']))
    {
        update_option('sucuri_wp_re', 'enabled');
    }
    else
    {
        update_option('sucuri_wp_re', 'disabled');
    }
}



/* Sucuri one-click hardening page. */
function sucuri_hardening_page()
{
    $U_ERROR = NULL;
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }
    include_once("sucuri_hardening.php");


    ?>
    <div class="wrap">
    <div id="icon-link-manager" class="icon32"><br /></div>
    <h2>Sucuri 1-Click WordPress Hardening</h2>
    <br class="clear"/>
    <div id="poststuff" style="width:55%; float:left;">
        <div class="postbox">
        <h3>Sucuri 1-click Hardening</h3>
        <div class="inside">
        <?php

            echo '<h2>Secure your WordPress with our one-click hardening.</h2>'; 

            sucuri_harden_version();
            echo "<hr />";
            sucuri_harden_removegenerator();
            echo "<hr />";
            sucuri_harden_upload();
            echo "<hr />";
            sucuri_harden_keys();
            echo "<hr />";
            sucuri_harden_wpconfig();
            echo "<hr />";
            sucuri_harden_readme();
            echo "<hr />";
            sucuri_harden_phpversion();
            echo "<hr />";
            echo '<b>If you have any question about these checks or this plugin, contact us at support@sucuri.net or visit <a href="http://sucuri.net">http://sucuri.net</a></b>';
        ?>
        </div>
        </div>
    </div>       
    </div>

    <?php
}



/* Sucuri malware scan page. */
function sucuri_malwarescan_page()
{
    $U_ERROR = NULL;
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }

    ?>


    <div class="wrap">
    <div id="icon-tools" class="icon32"><br /></div>
    <h2>Sucuri Malware Scanner</h2>
    <br class="clear"/>
    <div id="poststuff" style="width:55%; float:left;">
        <div class="postbox">
        <h3>Sucuri Malware Scanner</h3>
        <div class="inside">

        <h4>Execute an external malware scan on your site, using the <a href="http://sucuri.net">Sucuri</a> scanner. It will alert you if your site is compromised with malware, spam, defaced or blacklisted</h4>
            
        <a target="_blank" href="http://sitecheck.sucuri.net/results/<?php echo home_url();?>">Scan now!</a>
        </div>
        </div>
    </div>       
    </div>

    <?php
}





/* Sucuri setting's page. */
function sucuri_settings_page()
{
    $U_ERROR = NULL;
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }


    /* Manual scan. */
    if(isset($_GET['manualscan']))
    {
        sucuri_do_scan();
    }


    /* Process post */
    if(isset($_POST['wpsucuri-modify-values']))
    {
        $U_ERROR = sucuri_modify_values();
        if($U_ERROR == NULL)
        {
            $U_ERROR = "Configuration changed successfully.";
        }
    }


    /* Default values */
    $sucuri_wp_key = NULL;
    $sucuri_activated = 0;


    /* If remediation (ip blocking is enabled. */
    $ck = get_option('sucuri_wp_re');
    $ck_val = ' checked="checked"';
    if($ck !== FALSE && $ck == 'disabled')
    {
        $ck_val = '';
    }


    /* Getting current key */
    $sucuri_wp_key = get_option('sucuri_wp_key');
    if($sucuri_wp_key === FALSE)
    {
    }
    else
    {
        $sucuri_wp_key = htmlspecialchars(trim($sucuri_wp_key));
        $sucuri_activated = 1;
    }

    ?> 

    <div class="wrap">
    <div id="icon-plugins" class="icon32"><br/></div>
    <h2>Sucuri Plugin</h2>
    <br class="clear"/>


    <?php
    if($U_ERROR != NULL)
    {
        echo '<div id="message" class="updated"><p>'.htmlspecialchars($U_ERROR).'</p></div>';
    }
    if($sucuri_activated == 0)
    {
        ?>
        <div id="poststuff" style="width:55%; float:left;">
            <div class="postbox">
            <h3>Plugin not activated</h3>
            <div class="inside">
            Your plugin is not configured yet. Please login to <a target="_blank" href="https://wordpress.sucuri.net">https://wordpress.sucuri.net</a> to get your authentication (API) key. <br />&nbsp;<br />Note, this plugin is only for Sucuri users. If you do not have an account, please sign up here: <a href="http://sucuri.net/signup">http://sucuri.net/signup</a>.
            </div>
            </div>
        </div>       
        <?php
    }
    ?>

    <div id="poststuff">
    <div style="width:55%; float:left;">
        <div class="postbox">
        <div class="handlediv" title="Click to toggle"><br /></div>
        <h3>Main settings</h3>
        <div class="inside">
            <form method="post">
            <input type="hidden" name="wpsucuri-modify-values" value="wpsucuri-modify-values" />
            <table class="form-table" style="margin-bottom:5px;">
            <tbody>
                <tr><td>
                <p>SUCURI API KEY (<i> get it from <a target="_blank" href="https://wordpress.sucuri.net">here</a></i>):<br />
                <input type="text" name="wpsucuri-newkey" id="wpsucuri-newkey" value="<?php if($sucuri_wp_key != NULL){echo $sucuri_wp_key;}?>" size="40" /></p>
                </td></tr>

                <tr><td><input type="checkbox" name="sucuri_ic" id="" value="1" checked="checked" disabled="disabled" /> Enables integrity monitoring for your files.</td></tr>

                <tr><td><input type="checkbox" name="sucuri_ea" id="" value="1" checked="checked" disabled="disabled" /> Enables audit trails and internal logs.</td></tr>

                <tr><td><input type="checkbox" name="sucuri_re" id="" value="1" <?php echo $ck_val;?>  /> Enables active responses (to block suspicious IP addresses)</td></tr>

                <tr><td> &nbsp; <input class="button-primary" type="submit" name="wpsucuri_domodify" value="Save values"></td><td> &nbsp; </td></tr>
            </tbody>
            </table>
            </form>
        </div>
        </div>
    </div>
    </div>




    <?php
    $errrm = NULL;


    /* Unblocking IP addresses */
    if(isset($_POST['wpsucuri_removeip']) && strlen($_POST['wpsucuri_removeip']) > 6)
    {
        $iptorm = explode(' ', htmlspecialchars($_POST['wpsucuri_removeip']));
        $pattern = "/^[0-9]+[\.][0-9]+[\.][0-9]+[\.][0-9]+$/";
        if(preg_match($pattern, $iptorm[0], $regs, PREG_OFFSET_CAPTURE, 0))
        {
            if($iptorm !== FALSE && !empty($iptorm) && strlen($iptorm[0]) > 4)
            {
                @unlink(ABSPATH."/wp-content/uploads/sucuri/blocks/".$iptorm[0]);
            }
        }
    }

    /* White list removal */
    if(isset($_POST['wpsucuri_whiteremoveip']) && strlen($_POST['wpsucuri_whiteremoveip']) > 6)
    {
        $iptorm = explode(' ', htmlspecialchars($_POST['wpsucuri_whiteremoveip']));
        $pattern = "/^[0-9]+[\.][0-9]+[\.][0-9]+[\.][0-9]+$/";
        if(preg_match($pattern, $iptorm[0], $regs, PREG_OFFSET_CAPTURE, 0))
        {
            @unlink(ABSPATH."/wp-content/uploads/sucuri/whitelist/".$iptorm[0]);
        }
    }

    /* Adding to the white list. */
    if(isset($_POST['wpsucuri_whiteaddip']) && strlen($_POST['wpsucuri_whiteaddip']) > 6)
    {
        $iptorm = htmlspecialchars(trim($_POST['wpsucuri_whiteaddip']));
        $pattern = "/^[0-9]+[\.][0-9]+[\.][0-9]+[\.][0-9]+$/";
        if(preg_match($pattern, $iptorm, $regs, PREG_OFFSET_CAPTURE, 0))
        {
            @touch(ABSPATH."/wp-content/uploads/sucuri/whitelist/".$iptorm);
        }
    }


    /* List of blocked ip addresses */
    $myblockedips = array();
    if(is_dir(ABSPATH."/wp-content/uploads/sucuri/blocks/"))
    {
        $listofips = scandir(ABSPATH."/wp-content/uploads/sucuri/blocks/");
        if(count($listofips > 3))
        {
            ?>
            <?php
            foreach($listofips as $uniqip)
            {
                if(strncmp($uniqip, "<", 1) == 0 ||
                   strncmp($uniqip, "#", 1) == 0 ||
                   strncmp($uniqip, ".", 1) == 0 ||
                   strncmp($uniqip, "b", 1) == 0 ||
                   strncmp($uniqip, "i", 1) == 0)
                {
                    continue;
                }
                $uniqip = htmlspecialchars($uniqip);
                $myblockedips[] = $uniqip; 
            }
        }
    }



    /* List of Whitelisted addresses */
    $mywhitelistips = array();
    if(is_dir(ABSPATH."/wp-content/uploads/sucuri/whitelist/"))
    {
        $listofips = scandir(ABSPATH."/wp-content/uploads/sucuri/whitelist/");
        if(count($listofips > 3))
        {
            ?>
            <?php
            foreach($listofips as $uniqip)
            {
                if(strncmp($uniqip, "<", 1) == 0 ||
                   strncmp($uniqip, "#", 1) == 0 ||
                   strncmp($uniqip, ".", 1) == 0 ||
                   strncmp($uniqip, "b", 1) == 0 ||
                   strncmp($uniqip, "i", 1) == 0)
                {
                    continue;
                }
                $uniqip = htmlspecialchars($uniqip);
                $mywhitelistips[] = $uniqip; 
                $totalwips++;
            }
        }
    }


    if($errrm != NULL)
    {
        echo '<div id="message" class="updated"><p>'.$errrm.'</p></div>';
    }
    else if(isset($_POST['wpsucuri_removeip']))
    {
        echo '<div id="message" class="updated"><p>IP address removed.</p></div>';
    }
    ?>


    <div id="poststuff" style="width:55%; float:left;">
        <div class="postbox">
            <h3>Blocked IP Addresses</h3>
            <div class="inside">

                <form action="" method="post">
                <?php 
                $totalips = 0;
                foreach($myblockedips as $mybip)
                {
                    echo '<input type="submit" name="wpsucuri_removeip" value="'.$mybip.' - Click to remove" /><br />';
                    $totalips = 1;
                }
                if($totalips == 0)
                {
                    echo "<p>No IP Address blocked so far.</p>";
                }
                ?>
                </form>
            </div>
        </div>
    </div>


     <div id="poststuff" style="width:55%; float:left;">
        <div class="postbox">
            <h3>White listed IP Addresses</h3>
            <div class="inside">

                <form action="" method="post">
                <?php 
                $totalips = 0;
                foreach($mywhitelistips as $mybip)
                {
                    echo '<input type="submit" name="wpsucuri_whiteremoveip" value="'.$mybip.' - Click to remove" /><br />';
                    $totalips = 1;
                }
                if($totalips == 0)
                {
                    echo "<p>No IP Address whitelisted so far.</p>";
                }
                ?>
                <br />
                <i>*Your current IP address: <?php echo $_SERVER["REMOTE_ADDR"]; if(isset($_SERVER['SUCURI_RIP'])){echo "(".$_SERVER['SUCURI_RIP'].")"; } ?></i>
                White list IP: <input type="text" name="wpsucuri_whiteaddip" id="wpsucuri_whiteaddip" value="" size="15" />
                <input type="submit" name="wpsucuri_whiteaddipbutton" value="White list" />
                
                </form>
            </div>
        </div>
    </div>

    
    


    </div>
       
    <?php
}



/* Sucuri's dashboard (main admin page) */
function sucuri_admin_page()
{
    $U_ERROR = NULL;
    if(!current_user_can('manage_options'))
    {
        wp_die( __('You do not have sufficient permissions to access this page.') );
    }

    $sucuri_wp_key = NULL;
    $sucuri_wp_key = get_option('sucuri_wp_key');
    if(isset($_POST['wpsucuri-modify-values']))
    {
        sucuri_settings_page();
        return(1);
    }
    else if($sucuri_wp_key === FALSE)
    {
        sucuri_settings_page();
        return(1);
    }


    /* Admin header. */
    echo '<div class="wrap">';
    ?>
    <iframe style="overflow:hidden" width="100%" height="2250px" src='https://wordpress.sucuri.net/single.php?k=<?php echo $sucuri_wp_key;?>'>
    Unable to load iframe.
    </iframe>
    <br />
    <hr />
    <h3><i>Plugin developed by <a href="http://sucuri.net">Sucuri Security</a> | <a href="https://support.sucuri.net">Support & Help</a></i></h3>
    </div>
    <?php
}



/* Deactivates the plugin. */
function sucuri_deactivate_scan() 
{
    wp_clear_scheduled_hook('sucuri_hourly_scan');
    delete_option('sucuri_wp_key');
}



/* Activates the hourly scan. */
function sucuri_activate_scan() 
{
    if(!is_dir(ABSPATH."/wp-content/uploads"))
    {
        @mkdir(ABSPATH."/wp-content/uploads/");
    }
    @mkdir(ABSPATH."/wp-content/uploads/sucuri");
    @touch(ABSPATH."/wp-content/uploads/sucuri/index.html");
    @mkdir(ABSPATH."/wp-content/uploads/sucuri/blocks");
    @mkdir(ABSPATH."/wp-content/uploads/sucuri/whitelist");
    @touch(ABSPATH."/wp-content/uploads/sucuri/index.html");
    @touch(ABSPATH."/wp-content/uploads/sucuri/blocks/index.html");
    @touch(ABSPATH."/wp-content/uploads/sucuri/whitelist/index.html");
    @file_put_contents(ABSPATH."/wp-content/uploads/sucuri/.htaccess", "\ndeny from all\n");

    if(!is_file(ABSPATH."/wp-content/uploads/sucuri/blocks/blocks.php"))
    {
        @file_put_contents(ABSPATH."/wp-content/uploads/sucuri/blocks/blocks.php", "\n<?php exit(0);\n\n", FILE_APPEND);
    }
}




/* Avoid running twice (save / set last running time) */
function sucuri_verify_run($type, $runtime)
{
    if(!is_readable(ABSPATH."/wp-content/uploads/sucuri/.firstrun"))
    {
        if(!is_dir(ABSPATH."/wp-content/uploads/sucuri"))
        {
            sucuri_activate_scan();
        }
        touch(ABSPATH."/wp-content/uploads/sucuri/.firstrun");
        return(true);
    }

    if(!is_readable(ABSPATH."/wp-content/uploads/sucuri/.".$type))
    {
        if(!is_dir(ABSPATH."/wp-content/uploads/sucuri"))
        {
            sucuri_activate_scan();
        }
        touch(ABSPATH."/wp-content/uploads/sucuri/.".$type);
        return(true);
    }

    $lastchanged = filemtime(ABSPATH."/wp-content/uploads/sucuri/.".$type);
    if($lastchanged > (time(0) - $runtime))
    {
        return(FALSE);
    }

    touch(ABSPATH."/wp-content/uploads/sucuri/.".$type);
    return(true);
}




/* Scans all files. */
function sucuri_scanallfiles($dir, $output)
{
    $dh = opendir($dir);
    if(!$dh)
    {
        return(0);
    }
    $printdir = $dir;

    while (($myfile = readdir($dh)) !== false)
    {
        if($myfile == "." || $myfile == "..")
        {
            continue;
        }

        if(strpos($myfile, "_sucuribackup.") !== FALSE)
        {
            continue;
        }
        if(is_dir($dir."/".$myfile))
        {
            if(($myfile == "cache") && (strpos($dir, "wp-content") !== FALSE))
            {
                continue;
            }
            if(($myfile == "w3tc") && (strpos($dir."/".$myfile, "wp-content/w3tc") !== FALSE))
            {
                continue;
            }
            if(($myfile == "sucuri") && (strpos($dir."/".$myfile, "wp-content/uploads") !== FALSE))
            {
                continue;
            }
            $output = sucuri_scanallfiles($dir."/".$myfile, $output);
        }
       
        else if((strpos($myfile, ".php") !== FALSE) ||
                (strpos($myfile, ".htm") !== FALSE) ||
                (strcmp($myfile, ".htaccess") == 0) ||
                (strcmp($myfile, "php.ini") == 0) ||
                (strpos($myfile, ".js") !== FALSE))
        {
            $output = $output.md5_file($dir."/".$myfile).filesize($dir."/".$myfile)." ".$dir."/".$myfile."\n";
        }

    }
    closedir($dh);
    return($output);
}



/* Executes the hourly scans. */
function sucuri_do_scan() 
{
    global $wp_version;
    $sucuri_wp_key = get_option('sucuri_wp_key');
    

    sucuri_debug_log("Running wp-cron (doscan).");
    if($sucuri_wp_key === FALSE)
    {
        return(NULL);
    }

    sucuri_debug_log("Running wp-cron (valid key)");
    if(sucuri_verify_run("sc", 5000) === FALSE)
    {
        return(NULL);
    }

    sucuri_debug_log("Running wp-cron (verify run passed)");
    $output = "";
    sucuri_send_log($sucuri_wp_key, "WordPress version: $wp_version", 1);
    sucuri_debug_log("Running wp-cron (wp version $wp_version)");
    if(strcmp($wp_version, "3.2.1") >= 0)
    {
        sucuri_debug_log("Running wp-cron (sending wp hashes)");
        $output = sucuri_scanallfiles(ABSPATH, $output);
        sucuri_debug_log("Running wp-cron (sending wp hashes completed 1)");
        sucuri_send_hashes($sucuri_wp_key, $output);
        sucuri_debug_log("Running wp-cron (sending wp hashes completed 2)");
    }
    sucuri_debug_log("Running wp-cron (finished)");
}



/* Sends the hashes to sucuri. */
function sucuri_send_hashes($sucuri_wp_key, $final_message)
{

    $response = wp_remote_post("https://wordpress.sucuri.net/", array(
	'method' => 'POST',
	'timeout' => 20,
	'redirection' => 5,
	'httpversion' => '1.0',
	'blocking' => true,
	'body' => array( 'k' => $sucuri_wp_key, 'send-hashes' => $final_message),
    ));

    if(is_wp_error($response))
    {
        return(1);
    }

    $doresult = $response['body'];
    if(strpos($doresult,"ERROR:") === FALSE)
    {
        if(strpos($doresult, "ERROR: Invalid") !== FALSE)
        {
            delete_option('sucuri_wp_key');
        }
        return(1);
    }
    else
    {
        return(0);
    }
}



/* Blocks an IP via our plugin (wp-admin only). */
function sucuri_block_wpadmin()
{
    /* Creating backup file */
    if(!is_dir(ABSPATH."/wp-content/uploads/sucuri/blocks/"))
    {
        @mkdir(ABSPATH."/wp-content/uploads/sucuri");
        @mkdir(ABSPATH."/wp-content/uploads/sucuri/blocks");
        @mkdir(ABSPATH."/wp-content/uploads/sucuri/whitelist");
        @touch(ABSPATH."/wp-content/uploads/sucuri/index.html");
        file_put_contents(ABSPATH."/wp-content/uploads/sucuri/.htaccess", "\ndeny from all\n");
        file_put_contents(ABSPATH."/wp-content/uploads/sucuri/blocks/blocks.php", "\n<?php exit(0);\n\n", FILE_APPEND);
    }
    if(isset($_SERVER['SUCURI_RIP']))
    {
        touch(ABSPATH."/wp-content/uploads/sucuri/blocks/".$_SERVER['SUCURI_RIP']);
    }
    else
    {
        touch(ABSPATH."/wp-content/uploads/sucuri/blocks/".$_SERVER['REMOTE_ADDR']);
    }

    //@file_put_contents(ABSPATH."/wp-content/uploads/sucuri/blocks/blocks.php",
    //                   "**".@date("r: ").$_SERVER["REMOTE_ADDR"]." Blocked Post request received at: ".
    //                   trim($_SERVER['REQUEST_URI'])."\nAgent: ".
    //                   $_SERVER['HTTP_USER_AGENT']."\n". print_r($_POST,1));

}



/* Sends the events to sucuri. */
function sucuri_send_log($sucuri_wp_key, $final_message, $ignore_res = 0)
{
    $response = wp_remote_post("https://wordpress.sucuri.net/", array(
	'method' => 'POST',
	'timeout' => 10,
	'redirection' => 5,
	'httpversion' => '1.0',
	'blocking' => true,
	'body' => array( 'k' => $sucuri_wp_key, 'send-event' => $final_message),
    ));

    if(is_wp_error($response))
    {
        return(-1);
    }

    $doresult = $response['body'];
    
    if($ignore_res == 1)
    {
        return(1);
    }

    if(strpos($doresult,"ERROR:") !== FALSE)
    {
        if(strpos($doresult, "ERROR: Invalid") !== FALSE)
        {
            delete_option('sucuri_wp_key');
        }
        return(0);
    }
    else if(strpos($doresult, "ACTION: BLOCK") !== FALSE)
    {
        
        $re = get_option('sucuri_wp_re');
        if($re !== FALSE && $re == 'disabled')
        {
            return(1);
        }

        return(1);
    }
    else if(strpos($doresult, "OK:") !== FALSE)
    {
        return(1);
    }
    else
    {
        return(0);
    }
}



/* Generates an audit event. */
function sucuri_event($severity, $location, $message) 
{
    $severity = trim($severity);
    $location = trim($location);
    $message = trim($message);

	
    $username = NULL;
    $user = wp_get_current_user();
    if(!empty($user->ID))
    {
        $username = $user->user_login;
    }
    $time = date('Y-m-d H:i:s', time());
	

    /* Fixing severity */
    $severity = (int)$severity;
    if ($severity < 0)
    {
        $severity = 1;
    }
    else if($severity > 5)
    {
        $severity = 5;
    }
        
    /* Setting remote ip. */
    $remote_ip = "local";
    if(isset($_SERVER['SUCURI_RIP']) && strlen($_SERVER['SUCURI_RIP']) > 4)
    {
        $remote_ip = $_SERVER['SUCURI_RIP'];
    }
    else if(isset($_SERVER['REMOTE_ADDR']) && strlen($_SERVER['REMOTE_ADDR']) > 4)
    {
        $remote_ip = $_SERVER['REMOTE_ADDR'];
    }


    /* Setting header block */
    $header = NULL;
    if($username !== NULL)
    {
        $header = '['.$remote_ip.' '.$username.']';
    }
    else
    {
        $header = '['.$remote_ip.']';
    }


    /* Making sure we escape everything. */
    $header = htmlspecialchars($header);


    /* Getting severity. */
    $severityname = "Info";
    if($severity == 0)
    {
        $severityname = "Debug";
    }
    else if($severity == 1)
    {
        $severityname = "Notice";
    }
    else if($severity == 2)
    {
        $severityname = "Info";
    }
    else if($severity == 3)
    {
        $severityname = "Warning";
    }
    else if($severity == 4)
    {
        $severityname = "Error";
    }
    else if($severity == 5)
    {
        $severityname = "Critical";
    }

    $sucuri_wp_key = get_option('sucuri_wp_key');
    if($sucuri_wp_key !== FALSE)
    {
        sucuri_send_log($sucuri_wp_key, "$severityname: $header: $message", 1);
    }

    return(true);
}



/** Hooks into WP **/
unset($_SERVER['SUCURI_RIP']);
if(isset($_SERVER["HTTP_X_FORWARDED_FOR"]) && 
   strlen($_SERVER["HTTP_X_FORWARDED_FOR"]) > 7 &&
   $_SERVER["HTTP_X_FORWARDED_FOR"] != $_SERVER['REMOTE_ADDR'])
{
    $_SERVER['SUCURI_RIP'] = trim($_SERVER["HTTP_X_FORWARDED_FOR"], "a..zA..Z%/. \t\n");
    $_SERVER['SUCURI_RIP'] = trim($_SERVER['SUCURI_RIP']);        
}


/* Detect plugins getting added/removed - and block IP addresses. */
if($_SERVER['REQUEST_METHOD'] == "POST")
{
    add_action('init', 'sucuri_process_prepost');
}
add_action('admin_init', 'sucuri_events_without_actions');
add_action('login head', 'sucuri_events_without_actions');
add_action('wp_authenticate', 'sucuri_events_without_actions');
add_action('login_form', 'sucuri_events_without_actions');


/* Activation / Deactivation actions. */
register_activation_hook(__FILE__, 'sucuri_activate_scan');
register_deactivation_hook(__FILE__, 'sucuri_deactivate_scan');

/* Hooks our scanner function to the hourly cron. */
add_action('sucuri_hourly_scan', 'sucuri_do_scan');

/* Sucuri's admin menu. */
add_action('admin_menu', 'sucuri_menu');

/* Removing generator */
remove_action('wp_head', 'wp_generator');

/* Global hooks/actions */
include_once('sucuri_hooks.php');
include_once('sucuri_actions.php');
