<?php

# TM-MISP web UI script for display IOC from Apex central and DSM
#


if(isset($_GET['url']) && (preg_match("/^([a-f0-9]{64})$/", strtolower($_GET['url'])) || preg_match('/^[0-9a-f]{40}$/i', strtolower($_GET['url'])))){
	//case file hash
include_once("./tmconfig.php");
	
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
	print("<a href='#' onclick=loadVT('".$_GET['url']."','".$_GET['div']."')>Try again</a>");
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
		include_once("./tmconfig.php");	
		
		
		$vt_link="https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=$vt_api_key&ip=".$_GET['url'];
	
	
	$vt_result=@file_get_contents($vt_link);
	if($vt_result === false){
	$error = error_get_last();
    $error = explode(': ', $error['message']);
    $error = trim($error[2]);
	print("<a href='#' onclick=loadVT('".$_GET['url']."','".$_GET['div']."')>Try again</a>");
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
	
	
	include_once("./tmconfig.php");	
		
		
		$vt_link="https://www.virustotal.com/vtapi/v2/url/report?apikey=$vt_api_key&resource=".$_GET['url'];
	//"positives": 2, "total": 80
	
	$vt_result=@file_get_contents($vt_link);
	if($vt_result === false){
	$error = error_get_last();
    $error = explode(': ', $error['message']);
    $error = trim($error[2]);
	print("<a href='#' onclick=loadVT('".$_GET['url']."','".$_GET['div']."')>Try again</a>");
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
	
	$valid = checkdnsrr($_GET['url'] , "A");
	if($valid){ // case domain
	
		
		include_once("./tmconfig.php");	
		
		
		$vt_link="https://www.virustotal.com/vtapi/v2/domain/report?apikey=$vt_api_key&domain=".$_GET['url'];
	//"positives": 2, "total": 80
	
	$vt_result=@file_get_contents($vt_link);
	if($vt_result === false){
	$error = error_get_last();
    $error = explode(': ', $error['message']);
    $error = trim($error[2]);
	print("<a href='#' onclick=loadVT('".$_GET['url']."','".$_GET['div']."')>Try again</a>");
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







$return_all_apex = json_decode(file_get_contents("/var/www/MISP/PyMISP/examples/list_apex_so.txt"));
$return_all_ds = json_decode(file_get_contents("/var/www/MISP/PyMISP/examples/list_ds_so.txt"));

	print("<html><head><title>TM-MISP Integration Portal</title>
		<meta charset='UTF-8'>
	<meta name='viewport' content='width=device-width, initial-scale=1'>
	<link rel='stylesheet' type='text/css' href='main.css'>
	</head><body>
		<div class=limiter>
		<div class=container-table100><h1>IOC List from MISP</h1><br>
			<div class=wrap-table100>
				<div class=table100>
	<table><thead>
	<tr class=table100-head><th class=column1>#</th><th class=column2>SHA256</th><th class=column3>SHA-1 / URL / Domain / IP</th><th class=column4>FileName</th><th class=column6>VirusTotal </th></tr></thead><tbody>
	<script type='text/javascript'>
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


");

$t=0;
$x=0;
$a=Array();
	foreach ($return_all_apex as $apex_key => $apex_value){
		#print("$apex_key");
		if(count($apex_value)<2){
			break;
		}
		for ($i=0;$i<count($apex_value);$i++){
			#print_r($apex_value[$i]);
			#print("<hr>");
			
			foreach($apex_value[$i] as $afield_name => $afield_value){
				if($afield_name === "content"){
					$aname_print=$afield_value;
				}
				if($afield_name === "notes" && preg_match("/MISP/",$afield_value)){
					$t++;
					array_push($a,strtolower($aname_print));
					#print "<p>$t. $aname_print</p>";
				}
			}
		}	
	}
	




 


$return_all_rule=$return_all_ds;


	$k=0;
	foreach ($return_all_rule as $globalrule => $array_of_rule){
		for ($i=0;$i<count($array_of_rule);$i++){
			foreach($array_of_rule[$i] as $field_name => $field_value){
				if($field_name === "sha256"){
					$name_print=$field_value;
				}
				if($field_name === "description" && preg_match("/MISP/",$field_value)){
					$k++;
					$name_print2="";
					$tmp=explode("=",$field_value);
					if(count($tmp)>1){
						
						$name_print2 = $tmp[1];
						$a = array_diff($a, array($tmp[1]));
					}
					$vt_link=$name_print;

					print("<tr><td class=column1>$k.</td><td class=column2>$name_print</td><td class=column3>$name_print2</td><td class=column4><div id=f_myDiv$k>&nbsp;</div></td><td class=column6 nowrap><div id=myDiv$k><a href='#' onclick=loadVT('$vt_link','myDiv$k')>View VT</a></div></td></tr>");
				}
			}
		}	
	}
	



	
	
	
	for($w=0;$w<count($a);$w++){
		
		print("<tr><td class=column1>".($k+$w+1).".</td><td class=column2></td><td class=column3>$a[$w]</td><td class=column4><div id=f_myDiv".($k+$w+1).">&nbsp;</div></td><td class=column6 nowrap><div id=myDiv".($k+$w+1)."><a href='#' onclick=loadVT('$a[$w]','myDiv".($k+$w+1)."')>View VT</a></div></td></tr>");
	}

	print("<tr><td class=column1>&gt;&gt;&gt;</td><td class=column2>Deep Security IOC: $k</td><td class=column3>Apex Central IOC: $t</td><td class=column4></td><td class=column6>Total: ".($k+$w)."</td></tr>");
	print("");
	print("</body></html>");
	print("</tbody></table>		</div>
			</div>
		</div>
	</div>");





?>
