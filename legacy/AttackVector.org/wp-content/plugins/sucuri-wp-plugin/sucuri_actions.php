<?php
/* Sucuri Security WordPress Plugin
 * Copyright (C) 2010-2012 Sucuri Security - http://sucuri.net
 * Released under the GPL - see LICENSE file for details.
 */

if(!defined('SUCURIWPSTARTED'))
{
    return(0);
}

   
add_action('add_attachment', 'sucuri_add_attachment', 50); 
add_action('create_category', 'sucuri_create_category', 50); 
add_action('delete_post', 'sucuri_delete_post', 50); 
add_action('private_to_published', 'sucuri_private_to_published', 50); 
add_action('publish_page', 'sucuri_publish_post', 50); 
add_action('publish_post', 'sucuri_publish_post', 50); 
add_action('publish_phone', 'sucuri_publish_post', 50); 
add_action('xmlrpc_publish_post', 'sucuri_publish_post', 50); 
add_action('add_link', 'sucuri_add_link', 50); 
add_action('switch_theme', 'sucuri_switch_theme', 50); 
add_action('delete_user', 'sucuri_delete_user', 50); 
add_action('retrieve_password', 'sucuri_retrieve_password', 50); 
add_action('user_register', 'sucuri_user_register', 50); 
add_action('wp_login', 'sucuri_wp_login', 50); 
add_action('wp_login_failed', 'sucuri_wp_login_failed', 50); 
add_action('login_form_resetpass', 'sucuri_reset_password', 50); 
