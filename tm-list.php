<?php


$return_all_apex = json_decode(file_get_contents("/var/www/MISP/PyMISP/examples/list_apex_so.txt"));
$return_all_ds = json_decode(file_get_contents("/var/www/MISP/PyMISP/examples/list_ds_so.txt"));

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
	//--------------------------------
print("		<div class=wrap-table100><br><br></div><div class=wrap-table100><h1>IOC List from MISP in Trend Micro <h3>[ <a href='tm-misp.php'>see MISP Waiting List IOC</a> ]</h3></h1></div>
			<div class=wrap-table100>
				<div class=table100>
	<table><thead>
	<tr class=table100-head><th class=column1>#</th><th class=column2>SHA256</th><th class=column3>SHA-1 / URL / Domain / IP</th><th class=column4>FileName</th><th class=column6>VirusTotal </th></tr></thead><tbody>



");

$t=0;
$x=0;
$a=Array();
if(strlen($return_all_apex)){
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
}
	




 


$return_all_rule=$return_all_ds;


	$k=0;
	foreach ($return_all_rule as $globalrule => $array_of_rule){
		for ($i=0;$i<count($array_of_rule);$i++){
			foreach($array_of_rule[$i] as $field_name => $field_value){
				if($field_name === "sha256"){
					$name_print=strtolower($field_value);
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

					print("<tr><td class=column1>$k.</td><td class=column2>$name_print</td><td class=column3>$name_print2</td><td class=column4><div id=f_myDiv".($k).">&nbsp;</div></td><td class=column6 nowrap><div id=myDiv".($k)."><a href='#' onclick=loadVT('$vt_link','myDiv".($k)."')>View VT</a></div></td></tr>");
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