<?php
// A wp-content/db.php drop-in for test/ext-db.sh (never shipped), shaped like HyperDB,
// LudicrousDB and Query Monitor: a subclass of wpdb defined outside class-wpdb.php, installed as
// $wpdb. Its query() overrides wpdb's and calls parent::query() (Query Monitor's shape), and
// sc_send() sends SQL on the connection itself (HyperDB's / LudicrousDB's shape). Both are the
// database layer: a plugin's SQL through either must still be charged to the plugin
// (#53 review, finding 1).
require_once ABSPATH . WPINC . '/class-wpdb.php';

class sc_dropin_db extends wpdb {
    public function query($query) {
        return parent::query($query);
    }

    public function sc_send($sql) {
        $r = mysqli_query($this->dbh, $sql);
        if ($r instanceof mysqli_result) {
            mysqli_free_result($r);
            return true;
        }
        return $r;
    }
}

$wpdb = new sc_dropin_db(DB_USER, DB_PASSWORD, DB_NAME, DB_HOST);
