<?php
/* Sucuri Security WordPress Plugin
 * Copyright (C) 2010-2012 Sucuri Security - http://sucuri.net
 * Released under the GPL - see LICENSE file for details.
 */
if(!defined('SUCURIWPSTARTED'))
{
    return(0);
}


function sucuri_add_attachment($id = NULL)
{
    if (is_numeric($id)) 
    {
        $postdata = get_post($id);
        $postname = $postdata->post_title;
    }
    sucuri_event(1, "core", "Attachment added to post. Id: $id, Name: $postname");
}


function sucuri_create_category($categoryid = NULL)
{
    if(is_numeric($categoryid))
    {
        $name = get_cat_name($categoryid);
    }
    sucuri_event(1, "core", "Category created. Id: $categoryid, Name: $name");
}

function sucuri_delete_post($id = NULL)
{
    //sucuri_event(3, "core", "Post deleted. Id: $id");
}

function sucuri_private_to_published($id = NULL)
{
    if (is_numeric($id)) 
    {
        $postdata = get_post($id);
        $postname = $postdata->post_title;
    }
    sucuri_event(2, "core", "Post state changed from private to published. Id: $id, Name: $postname");
}

function sucuri_publish_post($id = NULL)
{
    if (is_numeric($id)) 
    {
        $postdata = get_post($id);
        $postname = $postdata->post_title;
    }
    sucuri_event(2, "core", "Post published (or edited after being published). Id: $id, Name: $postname");
}


function sucuri_add_link($id)
{
    if(is_numeric($id))
    {
        $linkdata = get_bookmark($id);
        $name = $linkdata->link_name;
        $url = $linkdata->link_url;
    }
    sucuri_event(2, "core", "New link added. Id: $id, Name: $name, URL: $url");
}


function sucuri_switch_theme($themename)
{
    sucuri_event(3, "core", "Theme modified to: $themename");
}

function sucuri_delete_user($id)
{
    sucuri_event(3, "core", "User deleted. Id: $id");
}

function sucuri_retrieve_password($name)
{
    sucuri_event(3, "core", "Password retrieval attempt by user $name");
}

function sucuri_user_register($id)
{
    if(is_numeric($id))
    {
        $userdata = get_userdata($id);
        $name = $userdata->display_name;
    }
    sucuri_event(3, "core", "New user registered: Id: $id, Name: $name");
}


function sucuri_wp_login($name)
{
    $displayname = get_profile('display_name', $name);

    sucuri_event(2, "core","User logged in. Name: $name");
}

function sucuri_wp_login_failed($name)
{
    sucuri_event(3, "core","User authentication failed. User name: $name");
}


function sucuri_reset_password($arg = NULL)
{
    if(isset($_GET['key']) )
    {
        /* Detecting wordpress 2.8.3 vulnerability - $key is array */
        if(is_array($_GET['key']))
        {
            sucuri_event(3, 'core', "IDS: Attempt to reset password by attacking wp2.8.3 bug.");
        }
    }
}



function sucuri_process_prepost()
{
    if($_SERVER['REQUEST_METHOD'] != "POST")
    {
        return(0);
    }


    /* Using the right ip address here. */
    $myip = $_SERVER['REMOTE_ADDR'];
    if(isset($_SERVER['SUCURI_RIP']))
    {
        $myip = $_SERVER['SUCURI_RIP'];
    }


    if(is_file(ABSPATH."/wp-content/uploads/sucuri/whitelist/$myip"))
    {
        return(0);
    }


    /* Blocking IP addresses in our block list. */
    if(is_file(ABSPATH."/wp-content/uploads/sucuri/blocks/$myip"))
    {
        wp_die("Denied acccess by <a href='http://sucuri.net'>Sucuri</a>");
    }        


    /* WordPress specific ignores */
    if($doblock == 0)
    {
        $_SERVER['REQUEST_URI'] = trim($_SERVER['REQUEST_URI']);
        if(strpos($_SERVER['REQUEST_URI'],"/wp-admin/admin-ajax.php") !== FALSE)
        {
            return(0);
        }
        else if(strpos($_SERVER['REQUEST_URI'], "/ajax_search.php") !== FALSE)
        {
            return(0);
        }
        else if(strpos($_SERVER['REQUEST_URI'], "/wp-admin/post.php") !== FALSE)
        {
            return(0);
        }
        else if(strpos($_SERVER['REQUEST_URI'], "/wp-cron.php") !== FALSE)
        {
            return(0);
        }
    }


    $response = wp_remote_post("http://cc.sucuri.net", array(
        'method' => 'POST',
        'timeout' => 10,
        'redirection' => 5,
        'httpversion' => '1.0',
        'blocking' => true,
        'body' => array( 'ip' => $myip, 
                         'from' => $_SERVER['SERVER_NAME'],
                         'path' => $_SERVER['REQUEST_URI'],
                         'ua' => $_SERVER['HTTP_USER_AGENT'],
                         'data' => print_r($_POST,1)),
    ));

    if(is_wp_error($response))
    {
        return(1);
    }

    $doresult = $response['body'];
    if(strpos($doresult, "BLOCK") !== FALSE)
    {
        $doblock = 1;
    }
    else
    {
        $doblock = 0;
    }


    if($doblock == 1)
    {
        $sucuri_wp_key = get_option('sucuri_wp_key');
        if($sucuri_wp_key != NULL)
        {
            sucuri_event(3, 'core', "IDS: Web firewall blocked access from: ".$myip);
        }
        sucuri_block_wpadmin();
        wp_die("Denied acccess by <a href='http://sucuri.net'>Sucuri</a>");
    }
}



function sucuri_events_without_actions()
{
    /* Using the right ip address here. */
    $myip = $_SERVER['REMOTE_ADDR'];
    if(isset($_SERVER['SUCURI_RIP']))
    {
        $myip = $_SERVER['SUCURI_RIP'];
    }

    /* Blocking IP addresses in our block list. */
    if(is_file(ABSPATH."/wp-content/uploads/sucuri/blocks/$myip"))
    {
        if(!is_file(ABSPATH."/wp-content/uploads/sucuri/whitelist/$myip"))
        {
            wp_die("Denied acccess by <a href='http://sucuri.net'>Sucuri</a>");
        }
    }        


    /* Plugin activated */
    if($_GET['action'] == "activate" && !empty($_GET['plugin']) && 
           strpos($_SERVER['REQUEST_URI'], 'plugins.php') !== false &&
           current_user_can('activate_plugins'))
    {
        $plugin = $_GET['plugin'];
        $plugin = strip_tags($plugin);
        $plugin = mysql_real_escape_string($plugin);
        sucuri_event(3, 'core', "Plugin activated: $plugin.");
    }

    /* Plugin deactivated */
    else if($_GET['action'] == "deactivate" && !empty($_GET['plugin']) && 
           strpos($_SERVER['REQUEST_URI'], 'plugins.php') !== false &&
           current_user_can('activate_plugins'))
    {
        $plugin = $_GET['plugin'];
        $plugin = strip_tags($plugin);
        $plugin = mysql_real_escape_string($plugin);
        sucuri_event(3, 'core', "Plugin deactivated: $plugin.");
    }

    /* Plugin updated */
    else if($_GET['action'] == "upgrade-plugin" && !empty($_GET['plugin']) && 
           strpos($_SERVER['REQUEST_URI'], 'wp-admin/update.php') !== false &&
           current_user_can('update_plugins'))
    {
        $plugin = $_GET['plugin'];
        $plugin = strip_tags($plugin);
        $plugin = mysql_real_escape_string($plugin);
        sucuri_event(3, 'core', "Plugin request to be updated: $plugin.");
    }

    /* WordPress updated */
    else if(isset($_POST['upgrade']) && isset($_POST['version']) && 
           strpos($_SERVER['REQUEST_URI'], 'update-core.php?action=do-core-reinstall') !== false &&
           current_user_can('update_core'))
    {
        $version = $_POST['version'];
        $version = strip_tags($version);
        $version = mysql_real_escape_string($version);
        sucuri_event(3, 'core', "WordPress updated (or re-installed) to version: $version.");
    }
}
?>
