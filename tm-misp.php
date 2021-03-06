<?php

# TM-MISP web UI script for display IOC waiting list to submit to Apex central and DSM
#
include_once("./tmconfig.php");
$ddd="";

if(!isset($_GET['url'])){
if(isset($ddd_url)){
	$arrContextOptions=array(
    "ssl"=>array(
        "verify_peer"=>false,
        "verify_peer_name"=>false,
    ),
); 
	$ddd=file_get_contents($ddd_url,false, stream_context_create($arrContextOptions));
	
	$ddd=explode("\n",$ddd);
	$cc=count($ddd);
	$ddd_a=Array();
	for($q=1;$q<$cc;$q++){
		$added=trim($ddd[$q]);
		if($added === "define category DDD_cnc_blacklists"){continue;}
		if($added === "define category DDD_wrs_blacklists"){continue;}
		if($added === "end") {continue;}
		if($added === "") {continue;}
		$added = trim(substr($added,1,-1));
		array_push($ddd_a,$added);
		
	}
	print("Trend Micro DDD IOC count = $cc");
	
	
}
}

	$file1="/var/www/MISP/PyMISP/examples/sending.txt";
	$file2="/var/www/MISP/PyMISP/examples/waiting.txt";
	

	
if(isset($_GET['add']) && isset($_GET['type'])){
	
	$mode="";$f_sha1="";
	//case sha256
	if(preg_match("/^([a-f0-9]{64})$/", strtolower($_GET['add']))){
		$mode="file_sha256";
		
		$f_sha1=$_GET['sha1'];
		if(strlen($f_sha1)>0 && !preg_match('/^[0-9a-f]{40}$/i', strtolower($_GET['sha1']))){
			print("mode=sha256 but sha1 is invalid");
			exit;
		}
	}
	//case sha1
	elseif(preg_match('/^[0-9a-f]{40}$/i', strtolower($_GET['add']))){
		$mode="file_sha1";
		
	}
	//case ip
	elseif(filter_var($_GET['add'], FILTER_VALIDATE_IP) !== false){
		$mode="ip";
	
	}
	//case url
	elseif(filter_var($_GET['add'], FILTER_VALIDATE_URL) !== false){
		$mode="url";
		
	}
	//case domain
	elseif(is_valid_domain_name($_GET['add'] )){
		$mode="domain";
		
	}
	
	if($mode != $_GET['type']){
		if($mode ===""){$mode="N/A";}
			print("mode invalid, $mode, ".$_GET['type']);
			exit;
		}
		if($mode === 'file_sha256'){
			$mode="file_sha256===".$_GET['sha1'];
		}
		print("writing, ");	
	
		$f=@fopen($file1,"a");
		if(!$f){
			print("error writing append file1");
			exit;
		}
		fwrite($f,$_GET['add']."===$mode\n");
		fclose($f);
		
		if(filesize($file2)){
		$whole_string = file_get_contents($file2);
		
		$entries = explode("\n",$whole_string);
//		print("waiting count = ".count($entries).", ");
		$f=@fopen($file2,"w");
		if(!$f){print("error remove queue");exit;}
		$c=0;
		for($i=0;$i<count($entries);$i++){
			if(preg_match("@".$_GET['add']."===@i",$entries[$i])){continue;}
			if(strlen($entries[$i])==0){continue;}
			fwrite($f,trim($entries[$i])."\n");
			$c++;
		}
		fclose($f);
		}
		header("location: tm-misp.php#end");
	print("finish update still left $c IOC to add<hr><a href='tm-misp.php'>Continue</a>");
exit;
}


if(isset($_GET['url']) && (preg_match("/^([a-f0-9]{64})$/", strtolower($_GET['url'])) || preg_match('/^[0-9a-f]{40}$/i', strtolower($_GET['url'])))){
	//case file hash

	
	$opts = [
    "http" => [
        "method" => "GET",
        "header" => "Accept-language: en\r\n" .
            "x-apikey: $vt_api_key\r\n"
    ]
];

$context = stream_context_create($opts);
	$vt_link="https://www.virustotal.com/api/v3/files/".$_GET['url'];
	
	
	$vt_result=@file_get_contents($vt_link,false, $context);
	if($vt_result === false){
	$error = error_get_last();
    $error = explode(': ', $error['message']);
    $error = trim($error[2]);
	print("<a href='#!' onclick=loadVT('".$_GET['url']."','".$_GET['div']."')>Try again</a>");
	exit;
	}
	if(preg_match("/error/",$vt_result)){
	print("error");
	}elseif(preg_match("/Invalid file hash/",$vt_result)){
	print("NO VT");
	}else{
		$tmp=explode("last_analysis_stats",$vt_result);
		$tmp2=explode("last_modification_date",$tmp[1]);
		//vt has 2 format
		//format 1: tmp2[0] has file name
		print("");
		if(preg_match("/meaningful_name/",$tmp2[0])){
			$tmp3=explode("meaningful_name",$tmp2[0]);
			$tmp4=explode(",",$tmp3[1]);
			$meaningful_name=substr($tmp4[0],4,-1);
			print($meaningful_name."===");
			$tmp5=explode("last_submission_date",$tmp[1]);
			$reult_line=explode("\n",$tmp5[0]);
		
		}else{
		//format 2: tmp2[1] has file name
		$name_line=explode("\n",$tmp2[1]);
		for($i=1;$i<count($name_line)-1;$i++){
			if(preg_match("/meaningful_name/",$name_line[$i])){
				$meaningful_name=substr($name_line[$i],32,-2);
			print($meaningful_name."===");
			}
		}
		//tmp2[0] result
		$reult_line=explode("\n",$tmp2[0]);
		}
		for($i=1;$i<count($reult_line)-1;$i++){
			if(preg_match("/malicious/",$reult_line[$i])){
			print (substr($reult_line[$i],0,-1)."<br>");
			}
			if(preg_match("/suspicious/",$reult_line[$i])){
			print (substr($reult_line[$i],0,-1)."<br>");
			}
			if(preg_match("/undetected/",$reult_line[$i])){
			print ($reult_line[$i]);
			}
		}
		
	print("");	
	
	}
	exit;
	
}elseif(isset($_GET['url']))
{
	
	$valid = (filter_var($_GET['url'], FILTER_VALIDATE_IP) !== false);
	if($valid){ //case ip
			
		
		
		$vt_link="https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=$vt_api_key&ip=".$_GET['url'];
	
	
	$vt_result=@file_get_contents($vt_link);
	if($vt_result === false){
	$error = error_get_last();
    $error = explode(': ', $error['message']);
    $error = trim($error[2]);
	print("<a href='#!' onclick=loadVT('".$_GET['url']."','".$_GET['div']."')>Try again</a>");
	exit;
	}
	//"detected_downloaded_samples": [{
	if(preg_match("/\"detected_downloaded_samples\"\: \[\{/",$vt_result)){
		print("===Seen Bad Sample");
	}else{
		print("===Look Good");
		
	}
		exit;
	}
	
	$valid = (filter_var($_GET['url'], FILTER_VALIDATE_URL) !== false);
	if($valid){ // case URL
	
	
		
		
		
		$vt_link="https://www.virustotal.com/vtapi/v2/url/report?apikey=$vt_api_key&resource=".$_GET['url'];
	//"positives": 2, "total": 80
	
	$vt_result=@file_get_contents($vt_link);
	if($vt_result === false){
	$error = error_get_last();
    $error = explode(': ', $error['message']);
    $error = trim($error[2]);
	print("<a href='#!' onclick=loadVT('".$_GET['url']."','".$_GET['div']."')>Try again</a>");
	exit;
	}
	if(preg_match("/Resource does not exist in the dataset/",$vt_result)){
		print("===N/A");
		exit;
	}
	//print($vt_result);//Resource does not exist in the dataset
	$tmp=explode("positives",$vt_result);
	//tmp[1]
	$tmp2=explode("scans",$tmp[1]);
	//tmp2[0] ": 1, "total": 79, "
	$tmp3 = explode(" ",$tmp2[0]);
	$detected = substr($tmp3[1],0,-1);
	$total = substr($tmp3[3],0,-1);
	print("===Detected: ".$detected."/".$total);
	
		exit;
	}
	
	$valid = is_valid_domain_name($_GET['url']);
	if($valid){ // case domain
	
		
			
		
		
		$vt_link="https://www.virustotal.com/vtapi/v2/domain/report?apikey=$vt_api_key&domain=".$_GET['url'];
	//"positives": 2, "total": 80
	
	$vt_result=@file_get_contents($vt_link);
	if($vt_result === false){
	$error = error_get_last();
    $error = explode(': ', $error['message']);
    $error = trim($error[2]);
	print("<a href='#!' onclick=loadVT('".$_GET['url']."','".$_GET['div']."')>Try again</a>");
	exit;
	}
	
//	print($vt_result);
	$tmp=explode("Verdict",$vt_result);
	//tmp[1]
	
	$tmp2=explode(",",$tmp[1]);
	//print($tmp2[0]);
	//": "safe"}
//	$tmp3 = explode(" ",$tmp2[0]);
	$detected = substr($tmp2[0],4,-1);
//	$total = substr($tmp3[3],0,-1);
	print("===Verdict: ".$detected);
		
		
		exit;
	}


	print("===N/A");
	exit;
}








$waiting_list = file_get_contents("/var/www/MISP/PyMISP/examples/waiting.txt");

		$aa=Array();
		$r=0;
		$waiting_list=explode("\n",$waiting_list);
		$count_waiting_list=count($waiting_list);

if(isset($_GET['action']) && $_GET['action']==='add_all'){
		$f=@fopen($file1,"a");
		if(!$f){
			print("error writing file1");
			exit;
		}
	for($run_add=0;$run_add<$count_waiting_list-1;$run_add++){
		
	
		fwrite($f,$waiting_list[$run_add]."\n");
		
		
	}
	fclose($f);
	$f=@fopen($file2,"w");
			if(!$f){
			print("error writing file2");
			exit;
		}
	fclose($f);
	header("Location: tm-misp.php#end");
	exit;
}


$sending_list = file_get_contents("/var/www/MISP/PyMISP/examples/sending.txt");

	print("<html><head><title>TM-MISP Integration Portal</title>
		<meta charset='UTF-8'>
	<meta name='viewport' content='width=device-width, initial-scale=1'>
	<link rel='stylesheet' type='text/css' href='main.css'>
	</head><body><script type='text/javascript'>
function loadVT(url_1,myDiv)
{
var xmlhttp;
if (window.XMLHttpRequest)
  {// code for IE7+, Firefox, Chrome, Opera, Safari
  xmlhttp=new XMLHttpRequest();
  }
else
  {// code for IE6, IE5
  xmlhttp=new ActiveXObject('Microsoft.XMLHTTP');
  }
xmlhttp.onreadystatechange=function()
  {
  if (xmlhttp.readyState==4)
    {
		tmp=xmlhttp.responseText.split('===');
    document.getElementById(myDiv).innerHTML=tmp[1];
	document.getElementById('f_'+myDiv).innerHTML=tmp[0];
    }
  }
xmlhttp.open('GET','tm-misp.php?url='+url_1+'&div='+myDiv,true);
xmlhttp.send();
}
</script>
		<div class=limiter><div class=container-table100>");
		
		
    $show = "<br>MISP IOC waiting queue was last modified: " . date ("F d Y H:i:s.", filemtime($file1)+18000)."<br>";
	$show .= "MISP submit queue was last modified: " . date ("F d Y H:i:s.", filemtime($file2)+18000)."<br>";

		if($count_waiting_list>1){
			
	$show .= "You can add all waiting list in single click: [<a href='tm-misp.php?action=add_all'>Add All Waiting List</a> ]<br>";		
		}

		//-----------------------------------
		print("<div class=wrap-table100><h1>MISP IOC Waiting to Add <h3>[ <a href='tm-list.php'>see current Trend Micro IOC</a> ]$show</h3></h1></div>
			<div class=wrap-table100>
				<div class=table100>
	<table><thead>
	<tr class=table100-head><th class=column1>#</th><th class=column2>SHA256</th><th class=column3>SHA-1 / URL / Domain / IP</th><th class=column4>DDD/Add?</th><th class=column5>FileName</th><th class=column6>VirusTotal </th></tr></thead><tbody>");

		for($d=0;$d<$count_waiting_list-1;$d++){
			if(preg_match("/file_sha256/",$waiting_list[$d])){
				$tmpx=explode("===",trim($waiting_list[$d]));
				array_push($aa,strtolower($tmpx[2]));
			}
			
		}
		$rr=0;
		for($r=0;$r<$count_waiting_list-1;$r++){
			$test=trim($waiting_list[$r]);
			if(!strlen($test)){continue;}
			$txt=explode("===",$test);
			if($txt[1]==='file_sha256'){
				$name_print=$txt[0];
				$name_print2=$txt[2];
				$txt[1]="file_sha256&sha1=".$txt[2];
			}else{
				if($txt[1]==='file_sha1' && in_array(strtolower($txt[0]), $aa)){
						continue;
				}
					$name_print="";
					$name_print2=$txt[0];
				
				
			}
			$ddd_yes = "No";
			if(in_array($name_print,$ddd_a) || in_array($name_print2,$ddd_a)){
				$ddd_yes = "Yes";
			}
			
		print("<tr><td class=column1>".($rr+1).".</td><td class=column2>$name_print</td><td class=column3>$name_print2</td><td class=column4>$ddd_yes / <a href='tm-misp.php?add=$txt[0]&type=$txt[1]'>Add</a></td><td class=column5><div id=f_myDiv".($rr+1).">&nbsp;</div></td><td class=column6 nowrap><div id=myDiv".($rr+1)."><a href='#!' onclick=loadVT('$txt[0]','myDiv".($rr+1)."')>View VT</a></div></td></tr>");
		$rr++;
		}
		
		print("</tbody></table></div></div>");
		//-----------------------------------------
				print("<div class=wrap-table100><br><br></div><div class=wrap-table100><h1>MISP Submit to Send to Trend Micro</h1></div>
			<div class=wrap-table100>
				<div class=table100>
	<table><thead>
	<tr class=table100-head><th class=column1>#</th><th class=column2>SHA256</th><th class=column3>SHA-1 / URL / Domain / IP</th><th class=column5>FileName</th><th class=column6>VirusTotal </th></tr></thead><tbody>");
		$aaa=Array();
		$ra=0;
		$sending_list=explode("\n",$sending_list);
		for($d=0;$d<count($sending_list)-1;$d++){
			if(preg_match("/file_sha256/",$sending_list[$d])){
				$tmpx=explode("===",trim($sending_list[$d]));
				array_push($aaa,strtolower($tmpx[2]));
			}
			
		}
		$raa=0;
		for($ra=0;$ra<count($sending_list)-1;$ra++){
			$test=trim($sending_list[$ra]);
		if(strlen($test)==0){continue;}	
			$txt=explode("===",$test);
			if($txt[1]==='file_sha256'){
				$name_print=$txt[0];
				$name_print2=$txt[2];
	
			}else{
				if($txt[1]==='file_sha1' && in_array(strtolower($txt[0]), $aaa)){
						continue;
				}
					$name_print="";
					$name_print2=$txt[0];
				
				
			}
			$raa++;
		print("<tr><td class=column1>".($raa).".</td><td class=column2>$name_print</td><td class=column3>$name_print2</td><td class=column5><div id=f_myDiv".($raa+$rr+1).">&nbsp;</div></td><td class=column6 nowrap><div id=myDiv".($raa+$rr+1)."><a href='#!' onclick=loadVT('$txt[0]','myDiv".($raa+$rr+1)."')>View VT</a></div></td></tr>");
		}
		
		

	print("</tbody></table>		</div>
			</div>
		</div>
	</div>");
	print("<a name=end></a></body></html>");

function is_valid_domain_name($domain_name)
{
    return (preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $domain_name) //valid chars check
            && preg_match("/^.{1,253}$/", $domain_name) //overall length check
            && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $domain_name)   ); //length of each label
}

?>
