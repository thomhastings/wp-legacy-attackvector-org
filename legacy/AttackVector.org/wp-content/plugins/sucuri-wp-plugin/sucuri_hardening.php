<?php
/* Sucuri Security WordPress Plugin
 * Copyright (C) 2010-2012 Sucuri Security - http://sucuri.net
 * Released under the GPL - see LICENSE file for details.
 */
if(!defined('SUCURIWPSTARTED'))
{
    return(0);
}



function sucuri_harden_error($message)
{
    return('<div id="message" class="error"><p>'.$message.'</p></div>');
}

function sucuri_harden_ok($message)
{
    return( '<div id="message" class="updated"><p>'.$message.'</p></div>');
}


function sucuri_harden_status($status, $type, $messageok, $messagewarn, 
                              $desc = NULL, $updatemsg = NULL)
{
    if($status == 1)
    {
        echo '<h4>'.
             '<img style="position:relative;top:5px" height="22" width="22"'. 
             'src="'.site_url().
             '/wp-content/plugins/sucuri-wp-plugin/images/ok.png" /> &nbsp; '.
             $messageok.'.</h4>';
        if($updatemsg != NULL){ echo $updatemsg; }
    }
    else
    {
        echo '<h4>'.
             '<img style="position:relative;top:5px" height="22" width="22"'. 
             'src="'.site_url().
             '/wp-content/plugins/sucuri-wp-plugin/images/warn.png" /> &nbsp; '.
             $messagewarn. '.</h4>';

        if($updatemsg != NULL){ echo $updatemsg; }
        if($type != NULL)
        {
        echo '<form action="" method="post">'.
             '<input type="hidden" name="wpsucuri-doharden" value="wpsucuri-doharden" />'.
             '<input type="hidden" name="'.$type.'" '.
             'value="'.$type.'" />'.
             '<input class="button-primary" type="submit" name="wpsucuri-dohardenform" value="Harden it!" />'.
             '</form><br />';
        }
    }
    if($desc != NULL)
    {
        echo "<i>$desc</i>";
    }

}


function sucuri_harden_version()
{
    global $wp_version;
    $cp = 0;
    $updates = get_core_updates();
    if (!is_array($updates))
    {
        $cp = 1;
    }
    else if(empty($updates))
    {
        $cp = 1;
    }
    else if($updates[0]->response == 'latest')
    {
        $cp = 1;
    }
    if(strcmp($wp_version, "3.2.1") <= 0)
    {
        $cp = 0;
    }
    

    sucuri_harden_status($cp, NULL, 
                         "WordPress is updated", "WordPress is not updated",
                         NULL);

    if($cp == 0)
    {
        echo "<i>Your current version ($wp_version) is not current. Please update it <a href='update-core.php'>now!</a></i>";
    }
    else
    {
        echo "<i>Your WordPress installation ($wp_version) is current.</i>";
    }
}



function sucuri_harden_removegenerator()
{
    /* Enabled by default with this plugin. */
    $cp = 1;
    
    sucuri_harden_status($cp, "sucuri_harden_removegenerator", 
                         "WordPress version properly hidden", NULL,
                         "It checks if your WordPress version is being hidden".
                         " from being displayed in the generator tag ".
                         "(enabled by default with this plugin).");
}



function sucuri_harden_upload()
{
    $cp = 1;
    $upmsg = NULL;
    if(!is_readable(ABSPATH."/wp-content/uploads/.htaccess"))
    {
        $cp = 0;
    }
    else
    {
        $cp = 0;
        $fcontent = file(ABSPATH."/wp-content/uploads/.htaccess");
        foreach($fcontent as $fline)
        {
            if(strpos($fline, "deny from all") !== FALSE)
            {
                $cp = 1;
                break;
            }
        }
    }

    if(isset($_POST['sucuri_harden_upload']) &&
       ($_POST['sucuri_harden_upload'] == 'sucuri_harden_upload') &&
       $cp == 0)
    {
        if(file_put_contents(ABSPATH."/wp-content/uploads/.htaccess",
                             "\n<Files *.php>\ndeny from all\n</Files>")===FALSE)
        {
            $upmsg = sucuri_harden_error("ERROR: Unable to create .htaccess file.");
        }
        else
        {
            $upmsg = sucuri_harden_ok("Completed. Upload directory successfully secured.");
            $cp = 1;
        }
    }

    sucuri_harden_status($cp, "sucuri_harden_upload", 
                         "Upload directory properly protected",
                         "Upload directory not protected",
                         "It checks if your upload directory allows PHP ".
                         "execution or if it is browsable.", $upmsg);
}   



function sucuri_harden_keys()
{
    $upmsg = NULL;
    $cp = 0;
    $wpconf = NULL;
    if(is_readable(ABSPATH."/wp-config.php"))
    {
        $wpconf = ABSPATH."/wp-config.php";
    }
    else if(is_readable(ABSPATH."/../wp-config.php"))
    {
        $wpconf = ABSPATH."/../wp-config.php";
    }
    else
    {
        /* Unable to find? */
        $cp = 1;
    }

    $wpcontent = file($wpconf);
    foreach($wpcontent as $wpline)
    {
        if(strncmp('define(\'NONCE_SALT\'', $wpline, 18) == 0 && 
           strlen($wpline) > 80)
        {
            $cp = 1;
        }
    }


    if(isset($_POST['sucuri_harden_keys']) &&
       ($_POST['sucuri_harden_keys'] == 'sucuri_harden_keys'))
    {
        $wpcontent = file($wpconf,FILE_IGNORE_NEW_LINES);
        $bkfile = ABSPATH."/wp-content/uploads/sucuri/wpconfig-saved-".time(0).".php";
        $newkeys = wp_remote_get("https://api.wordpress.org/secret-key/1.1/salt/");
        if(is_wp_error( $newkeys))
        {
            $upmsg = sucuri_harden_error("Unable to get new keys from wordpress.org. Not proceeding.");
        }
        else if(strpos($newkeys['body'], "LOGGED_IN_SALT") === FALSE)
        {
            $upmsg = sucuri_harden_error("Unable to get proper new keys from wordpress.org. Not proceeding.");
        }
        else if(!is_writable($wpconf))
        {
            $upmsg = sucuri_harden_error("Unable to write to your configuration file (check permissions). Not proceeding.");
        }

        else if(rename($wpconf, $bkfile) === FALSE)
        {
            $upmsg = sucuri_harden_error("Unable to backup current configuration. Not proceeding.");
        }
        else if(!($fp = fopen($wpconf, "w")))
        {
            $upmsg = sucuri_harden_error("Unable to write to your configuration file (check perms). Not proceeding.");
        }
        else
        {
            $wrote = 0;
            foreach($wpcontent as $wpline)
            {
                if(strncmp($wpline, "define('AUTH_KEY'",16) == 0)
                {
                    continue; 
                }
                if(strncmp($wpline, "define('SECURE_AUTH_KEY'",20) == 0)
                {
                    continue; 
                }
                if(strncmp($wpline, "define('LOGGED_IN_KEY'",16) == 0)
                {
                    continue; 
                }
                if(strncmp($wpline, "define('NONCE_KEY'",16) == 0)
                {
                    continue; 
                }
                if(strncmp($wpline, "define('AUTH_SALT'",16) == 0)
                {
                    continue; 
                }
                if(strncmp($wpline, "define('SECURE_AUTH_SALT'",20) == 0)
                {
                    continue; 
                }
                if(strncmp($wpline, "define('LOGGED_IN_SALT'",20) == 0)
                {
                    continue; 
                }
                if(strncmp($wpline, "define('NONCE_SALT'",16) == 0)
                {
                    continue; 
                }
                if(strncmp($wpline, "require_once(ABS",16) == 0)
                {
                    if($wrote == 0){fwrite($fp, $newkeys['body']);}
                    $wrote = 1;
                }
                $wpline = trim($wpline, "\r");
                fwrite($fp, $wpline."\n"); 
            }
            fclose($fp);
            $upmsg = sucuri_harden_ok("New set of keys created. You will be now logged out.");
        }
    }

    sucuri_harden_status($cp, NULL, 
                         "WordPress secret keys and salts properly created",
                         "WordPress secret keys and salts not set. We recommend creating them for security reasons",
                         "It checks whether you have proper random keys/salts ".
                         "created for WordPress. They should be created when ".
                         "you first install WordPress and regenerated if you ".
                         "have been hacked recently.", 
                         $upmsg);

    $rm = "Create your security keys now!";
    if($cp == 1)
    {
        $rm = "Generate new keys for you!";
    }
    echo '<br />&nbsp;<br />';
    echo '<form action="" method="post">'.
         '<input type="hidden" name="wpsucuri-doharden" value="wpsucuri-doharden" />'.
         '<input type="hidden" name="sucuri_harden_keys" '.
         'value="sucuri_harden_keys" />'.
         '<input class="button-primary" type="submit" name="wpsucuri-dohardenform" value="'.$rm.'" />'.
         '</form><br />';
    echo '<b>*You will be logged out after creating new keys. '.
         '</b>';
}



function sucuri_harden_wpconfig()
{
    $upmsg = NULL;
    $cp = 0;
    if(!is_readable(ABSPATH."/wp-config.php"))
    {
        $cp = 1;
    }
    else if(is_readable(ABSPATH."/../wp-config.php"))
    {
        $cp = 1;
    }
    if(is_readable(ABSPATH."/../index.php"))
    {
        $cp = 1;
    }
    if(is_readable(ABSPATH."/../index.html"))
    {
        $cp = 1;
    }

    if(isset($_POST['sucuri_harden_wpconfig']) &&
       ($_POST['sucuri_harden_wpconfig'] == 'sucuri_harden_wpconfig') &&
       $cp == 0)
    {
        if(rename(ABSPATH."/wp-config.php",ABSPATH."/../wp-config.php")===FALSE)
        {
            $upmsg = sucuri_harden_error("Unable to rename wp-config.php.");
        }
        else
        {
            $cp = 1;
            $upmsg = sucuri_harden_ok("Completed. WP-config renamed.");
        }
    }

    sucuri_harden_status($cp, "sucuri_harden_wpconfig", 
                         "Configuration file (wp-config.php) properly secured",
                         "Configuration file (wp-config.php) in the main WordPress directory. Not recommended",
                         "It checks whether your wp-config.php file is present ".
                         "in the default directory (instead of above one dir)", 
                         $upmsg);
}



function sucuri_harden_readme()
{
    $upmsg = NULL;
    $cp = 0;
    if(!is_readable(ABSPATH."/readme.html"))
    {
        $cp = 1;
    }

    if(isset($_POST['sucuri_harden_readme']) &&
       ($_POST['sucuri_harden_readme'] == 'sucuri_harden_readme') &&
       $cp == 0)
    {
        if(unlink(ABSPATH."/readme.html") === FALSE)
        {
            $upmsg = sucuri_harden_error("Unable to remove readme file.");
        }
        else
        {
            $cp = 1;
            $upmsg = sucuri_harden_ok("Readme file removed.");
        }
    }

    sucuri_harden_status($cp, "sucuri_harden_readme", 
                         "Readme file properly deleted",
                         "Readme file not deleted and leaking the WordPress version",
                         "It checks whether you have the readme.html file ".
                         "available that leaks your WordPress version.", $upmsg);
}





function sucuri_harden_phpversion()
{
    $phpv = phpversion();

    if(strncmp($phpv, "5.", 2) < 0)
    {
        $cp = 0;
    }
    else
    {
        $cp = 1;
    }

    sucuri_harden_status($cp, NULL, 
                         "Using an updated version of PHP (v $phpv)",
                         "The version of PHP you are using ($phpv) is not current. Not recommended and not supported",
                         "It checks if you have the latest version of PHP installed.", NULL);
}
?>
