<?php

define("DB_HOST", "");
define("DB_USER", "");
define("DB_PASS", "");

class sslCert
{
    protected $cert_path = '/foo/bar/letsencrypt/live';
    protected $disallow = array('nevhodna-domena-k-certifikaci.tld'); //speciální, či nefunkční certifikáty - neeliškovské
    protected $db;
    protected $dbs = ['databaze1', 'databaze2'];
    protected $times;
    protected $host_path = "/foo/bar/apache2/sites-enabled";
    public $certs_info_arr;

    public function __construct()
    {
        $this->createDBConnection();
        $this->dbs = $this->db->query("SELECT dbname FROM edb_dbs.dbs")->fetch_all(MYSQLI_ASSOC);
        $this->methodStart('SSL Handler');
        $this->autoCall();
    }
    public function __destruct()
    {
        $this->methodEnd('SSL Handler');
    }

    public function autoCall()
    {
        global $argv;
        //respects arguments order
        if (is_array($argv) && !empty($argv)) {
            foreach ($argv as $arg) {
                switch (strtolower($arg)) {
                    case "-updatedb": $this->updateDB(); break;
                    case "-renewall": $this->renewAll(); break;
                    case "-renew10": $this->renew10(); break;
                    case "-renew50": $this->renew50(); break;
                    case "-certnew": $this->certNewDomains(); break;
                    case "-setup": $this->setupMacro(); break;
                    case "-addnew": $this->certNewDomains(); break;
                    case "-queue": $this->proccessCallQueue(); break;
                    case "/usr/local/bin/cert.php": break;
                    default:
                        /*other callable methods by argument*/
                        echo "CERT.PHP CALLED WITHOUT ARGUMENT\nUSE ONE OF THESE ARGUMENTS:\n-updatedb\n-renewAll\n-renew10\n-renew50\n-certnew\n-setup\n-addnew\n-queue\nCalled arg: ".strtolower($arg);
                        break;
                }
            }
        }
    }

    protected function createDBConnection()
    {
        $this->db = new mysqli(DB_HOST, DB_USER, DB_PASS, "certbot");
    }

    protected function getCertInfo($dir)
    {
        $cert_info_arr = array();
 
        $cert = $this->cert_path."/".$dir."/cert.pem";

        $domains = shell_exec("cat " . $cert . " | openssl x509 -text | grep DNS:");
        $domains = str_replace(array(",", "DNS:", "\n", "                "), "", $domains);
        $not_after = shell_exec("cat " . $cert . " | openssl x509 -text | grep \"Not After\"");
        $not_after = str_replace(array("            Not After : ","\n"), "", $not_after);
        $time_after = strtotime($not_after);
        $cert_info_arr["domains"] = $domains;
        $cert_info_arr["not_after"] = $not_after;
        $cert_info_arr["time_after"] = $time_after;
        $cert_info_arr["dir"] = $dir;

        if ($time_after<strtotime("+15 days")) {
            //$cert_info_arr["renewal_string"] = "certbot-auto certonly --apache --preferred-challenge http-01 --expand --noninteractive --quiet --agree-tos -d ".str_replace(" ",",",$domains);
        }
        $cert_info_arr["renewal_string"] = "/snap/bin/certbot certonly --apache --preferred-challenges http-01 --expand --noninteractive --quiet --agree-tos -d ".str_replace(" ", ",", $domains);
        return $cert_info_arr;
    }

    protected function getCerts()
    {
        if (!empty($this->certs_info_arr)) {
            return;
        }

        $dirs = scandir($this->cert_path);
        foreach ($dirs as $dir) {
            if (!is_dir($this->cert_path."/".$dir) || $dir=="." || $dir == "..") {
                continue;
            }
            $this->certs_info_arr[$dir] = $this->getCertInfo($dir);
            if (isset($this->certs_info_arr[$dir]) && empty($this->certs_info_arr[$dir])) {
                unset($this->certs_info_arr[$dir]);
            }
        }
        return;
    }

    public function generateTable()
    {
        echo "<pre>";
        var_dump($this->certs_info_arr);
    }
    
    protected function saveOneToDB($cert_arr)
    {
        //save to db (choose if update or insert)
        $sql = "INSERT INTO `certificates` (`cert`, `valid_to`, `last_attempt`, `domains`, `havefiles`,`deleted`,`message`)
                VALUES ('".$cert_arr['dir']."', '".date("Y-m-d H:i:s", $cert_arr['time_after'])."', NOW() - INTERVAL 1 DAY, '".$cert_arr['domains']."',".$cert_arr['hf'].", 0,'')
                ON DUPLICATE KEY UPDATE `valid_to`='".date("Y-m-d H:i:s", $cert_arr['time_after'])."',`domains`='".$cert_arr['domains']."', `havefiles`=".$cert_arr['hf'];
        $this->db->query($sql);
    }
    protected function callCertOnly($domains = "",$droot)
    {
        if (!empty($domains)) {
            $shell = shell_exec("/snap/bin/certbot certonly --webroot -w ".$droot." --preferred-challenges http-01 --expand --noninteractive --agree-tos -d " . $domains);
        }
        return $shell;
    }

    protected function getDomainsDueToRenew($limit = 10)
    {
        $qlimit = "";
        if ($limit>0) {
            $qlimit = "LIMIT ".$limit;
        }
        $today = date("Y-m-d 00:00:00");
        $nextMonth = date("Y-m-d 00:00:00", strtotime('+10 days'));
        $sql = "SELECT * FROM `certificates` WHERE `valid_to`<'".$nextMonth."' AND `last_attempt`<'".$today."' ORDER BY  `havefiles` DESC, `valid_to` ASC ".$qlimit;
        return $this->db->query($sql)->fetch_all(MYSQLI_ASSOC);
    }

    protected function getDomains()
    {
        $sql = "SELECT * FROM `certificates` ORDER BY `cert` ASC";
        return $this->db->query($sql)->fetch_all(MYSQLI_ASSOC);
    }

    protected function getNotSpecialDomains()
    {
        $where = "`cert` NOT LIKE '%".implode("%' AND `cert` NOT LIKE '%", $this->disallow)."%'";
        $sql = "SELECT * FROM `certificates` WHERE ".$where." AND `deleted`=0 AND `havefiles`=1 ORDER BY `cert` ASC";
        return $this->db->query($sql)->fetch_all(MYSQLI_ASSOC);
    }

    protected function getCertFromMessage($string){
        $pos = strpos($string,"/foo/bar/letsencrypt/live/");
        if($pos !== FALSE){
            $string = substr($string, $pos, (strpos($string, "/fullchain.pem")-$pos));
            $string = str_replace("/foo/bar/letsencrypt/live/", "", $string);
            return $string;
        }
        return false;
    }

    protected function saveInfoToDomain($db_cert, $succ, $message)
    {
        $count = 0;
        if (!$succ) {
            $count = $db_cert["count_attempt"]+1;
            $valid_to = $db_cert["valid_to"];
        } else {
            $valid_to = date("Y-m-d 00:00:00", strtotime("+3 months"));
        }
        $cert = $this->getCertFromMessage($message);
        $setCert="";
        if($cert){
            $setCert = "`cert`='".$cert."', `havefiles`=1,";
        }
        $id = $db_cert['id'];
        $sql = "UPDATE `certificates` SET ".$setCert." `valid_to`='".$valid_to."', `last_attempt` = NOW(), `count_attempt` = '".$count."', `message` = '".$this->db->real_escape_string($message)."' WHERE `id`='".$id."'";

        $this->db->query($sql);
    }

    protected function isSucc($message)
    {
        if (strpos($message, "fail")!==false || strpos($message, "error")!==false || empty($message)) {
            return false;
        }
        return true;
    }

    protected function renew($limit = 10)
    {
        $db_certs = $this->getDomainsDueToRenew($limit);
        foreach ($db_certs as $db_cert) {
            $domains = str_replace(" ", ",", $db_cert['domains']);
            $droot = $db_cert['dir'];
            $message = $this->callCertOnly($domains,$droot);
            $succ = $this->isSucc($message);
            echo $db_cert['cert']." ".str_replace("\n", " ", $message)." ".var_export($succ, true)."\n";
            $this->saveInfoToDomain($db_cert, $succ, $message);
        }
    }
    protected function reloadApache()
    {
        shell_exec("/foo/bar/init.d/apache2 reload");
    }

    protected function clearDB()
    {
        $domains = $this->getDomains();
        foreach ($domains as $domain) {
            if (!is_dir($this->cert_path."/".$domain['cert'])) {
                $certs[] = $domain['cert'];
            }
        }
        if (!empty($certs)) {
            $this->removeCertsDB($certs);
        }
    }
    protected function removeCertsDB($certs)
    {
        $sql = "UPDATE `certificates` SET `havefiles` = 0 WHERE `cert` IN ('".implode("','", $certs)."')";
        $this->db->query($sql);
    }

    protected function getAllCertDomains()
    {
        $sql = "SELECT domains FROM certificates WHERE havefiles = 1";
        $db_domains = $this->db->query($sql)->fetch_all(MYSQLI_ASSOC);
        $domains = array();
        foreach ($db_domains as $dd) {
            $domains = array_merge(explode(" ", $dd['domains']), $domains);
        }
        return $domains;
    }
    protected function getOneIfCertExists($cert){
        $sql = "SELECT `domains`, `cert` FROM certificates WHERE cert LIKE '".$cert."%' LIMIT 1";
        $db_domains = $this->db->query($sql)->fetch_assoc();
        if(!empty($db_domains)){
            return $db_domains;
        }
        return false;
    }
    public function certNewDomains()
    {
        $this->methodStart(__FUNCTION__);
        $certDomains = $this->getAllCertDomains();
        $notIn = " AND `value` NOT IN ('".implode("','", $certDomains)."')";
        $notLike = " AND `value` NOT LIKE '%.propeople.cz%' AND `value` NOT LIKE '%spektrumzdravi.cz%' AND `value` NOT LIKE '%webyedb.cz%'";
        
        $sqlTpl = "SELECT `value` FROM `{DBNAME}`.`settings` WHERE `name`='alias' " . $notLike . $notIn ." GROUP BY `value`";
        $sqlArr=[];
        foreach ($this->dbs as $db) {
            $sqlArr[] = str_replace("{DBNAME}", $db['dbname'], $sqlTpl);
        }
        $sql = implode("\n UNION \n", $sqlArr);
        $rows = $this->db->query($sql)->fetch_all(MYSQLI_ASSOC);
        $i = 0;

        foreach ($rows as $row) {
            $row = $row['value'];
            if (empty($row)) {
                continue;
            }
            $ip = gethostbyname($row);
            if ($ip != "IP_SERVERU") {
                continue;
            }
            $d = array_reverse(explode(".", $row)); // 0 -> TLD, 1->base_domain, 2 -> subdomain...
            if (!isset($aliases[$d[1] . "." . $d[0]])) { //isset base_domain.tld
            $aliases[$d[1] . "." . $d[0]][] = $d[1] . "." . $d[0];
                if (!isset($aliases[$d[1] . "." . $d[0]]['have_base'])) {
                    $aliases[$d[1] . "." . $d[0]]['have_base'] = false;
                }
            }
            if ($d[1] . "." . $d[0] == $row) {
                $aliases[$d[1] . "." . $d[0]]['have_base'] = true;
            }

            if (!in_array($row, $aliases[$d[1] . "." . $d[0]])) {
                $aliases[$d[1] . "." . $d[0]][] = $row;
            }
        }

        unset($rows);
        unset($row);
        $i = 0;
        foreach ($aliases as $key => $alias_set) {
            $cert = $key;
            $domains = "";
            $c = 0;

            //v základu vždy přidáme verzi s www
            if ($alias_set['have_base']) {
                $alias_set[] = "www." . $key;
            } else {
                $alias_set[0];
            }

            //pokud přidáváme subdoménu k existujícímu certifikátu
            if (!in_array($key, $this->disallow)) {
                $existsDomians = $this->getOneIfCertExists($cert);
                if($existsDomians){
                    $cert = $existsDomians['cert'];
                    $existsDomiansArr = explode(" ",$existsDomians['domains']);
                    $alias_set = array_merge($existsDomiansArr,$alias_set);
                }
            }
            $shell = "";
            $alias_set = array_unique($alias_set);
            if ($alias_set['have_base'] != true) { //nemá základní doménu - rozdělíme tedy do jednotlivých certifikátů
                unset($alias_set['have_base']);
                foreach ($alias_set as $alias) {
                    $cert_arr['time_after'] = "0000-00-00 00:00:00";
                    $cert_arr['dir'] = $alias;
                    $cert_arr['domains'] = $alias;
                    $cert_arr['hf'] = 0;
                    $this->saveOneToDB($cert_arr);
                }
            } else {//má základní doménu - sjednotíme certifikáty pod jeden
                unset($alias_set['have_base']);
                $max = count($alias_set);
                foreach ($alias_set as $alias) {
                    if (is_string($alias) && !empty($alias)) {
                        $c ++;
                        $domains .= $alias;
                        if ($c != $max) {
                            $domains .= " ";
                        }
                    }
                }

                if (!empty($domains)) {
                    $cert_arr['time_after'] = "0000-00-00 00:00:00";
                    $cert_arr['dir'] = $cert;
                    $cert_arr['domains'] = $domains;
                    $cert_arr['hf'] = 0;
                    $this->saveOneToDB($cert_arr);
                }
            }
            echo $shell;
        }
        $this->methodEnd(__FUNCTION__);
    }

    public function setupMacro()
    {
        $this->methodStart(__FUNCTION__);
        $this->clearDB();
        $domains = $this->getNotSpecialDomains();
        $ssl_macro_use = "";

        foreach ($domains as $domain) {
            $ssl_macro_use .= 'Use SSL_MACRO_HOST "' . $domain['domains'] . '" '. $domain['cert']. "\n";
        }
        
        file_put_contents($this->host_path . "/ssl_macro_use.conf", $ssl_macro_use);
        $this->reloadApache();
        $this->methodEnd(__FUNCTION__);
    }

    public function renewAll()
    {
        $this->methodStart(__FUNCTION__);
        $return = $this->renew(0);
        $this->methodEnd(__FUNCTION__);
        return $return;
    }

    public function renew10()
    {
        $this->methodStart(__FUNCTION__);
        $return = $this->renew(10);
        $this->methodEnd(__FUNCTION__);
        return $return;
    }

    public function renew50()
    {
        $this->methodStart(__FUNCTION__);
        $return = $this->renew(50);
        $this->methodEnd(__FUNCTION__);
        return $return;
    }

    public function updateDB()
    {
        $this->methodStart(__FUNCTION__);
        $this->clearDB();
        $this->getCerts();
        
        foreach ($this->certs_info_arr as $cert_arr) {
            $cert_arr['hf'] = 1;
            $this->saveOneToDB($cert_arr);
        }
        $this->methodEnd(__FUNCTION__);
    }
    public function proccessCallQueue(){
        $this->methodStart(__FUNCTION__);

        $content = file_get_contents("/foo/bar/bin/call_queue");
        file_put_contents("/foo/bar/bin/call_queue","");
        $cmds = explode("\n",$content);
        foreach($cmds as $cmd){
            if(!empty($cmd)){
                exec($cmd);
            }
        }
        $this->methodEnd(__FUNCTION__);
    }

    public function __get($variable)
    {
        if ($variable == "certs_info_arr") {
            $this->getCerts();
            return $this->certs_info_arr;
        }
        return null;
    }

    protected function methodStart($method)
    {
        $this->times[$method]['start'] = microtime(true);
        echo "\n>>>>>Calling ".$method." in ".$this->timeNow()."<<<<<\n";
    }

    protected function methodEnd($method)
    {
        $this->times[$method]['end'] = microtime(true);
        echo "\n>>>>>Ending ".$method." in ".$this->timeNow()." takes ".$this->timeDifference($method)." s<<<<<\n";
    }

    protected function timeNow()
    {
        $now = DateTime::createFromFormat('U.u', microtime(true));
        return $now->format("m-d-Y H:i:s.u");
    }
    protected function timeDifference($method)
    {
        return ($this->times[$method]['end']-$this->times[$method]['start']);
    }

}
$sslCert = new sslCert();
