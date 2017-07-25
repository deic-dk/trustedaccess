function toggleDav() {
	 $.ajax({
		 url: OC.webroot+'/index.php/apps/trustedaccess/api/v1/toggledav',
		 data: {
			 toggle: true
		 },
		 dataType:'json',
		 type: 'GET',
		beforeSend: function(xhr) {
			xhr.setRequestHeader('OCS-APIREQUEST', 'true');
		}
	});
}

function saveSubject(){
	var dn = $('input#ssl_cert_dn').val();
	if(typeof dn === 'undefined'){
		OC.msg.finishedSaving('#chooser_msg', {status: 'error', data: {message: "Empty subject"}});
		return false;
	}
	$.ajax(
			OC.webroot+'/index.php/apps/trustedaccess/api/v1/setcertdn', {
		 type:'POST',
		  data:{
			  dn: dn
		 },
		 dataType:'json',
		 success: function(s){
			 if(s.error){
				 OC.msg.finishedSaving('#chooser_msg', {status: 'success', data: {message: s.error}});
			 }
			 else{
				 //$("#chooser_msg").html("Subject saved");
				 $('#chooser_msg').show();
				 $('#chooser_msg').removeClass('error');
				 OC.msg.finishedSaving('#chooser_msg', {status: 'success', data: {message: s.message}});
			 }
		 },
		error:function(s){
			 $('#chooser_msg').removeClass('success');
			 OC.msg.finishedSaving('#chooser_msg', {status: 'error', data: {message: "Unexpected error"}});
		}
	});
}

$(document).ready(function(){
  $('#allow_internal_dav').click(function(){
  	toggleDav();
    //alert( $(this).attr("id") );
  });
  
  $('#chooser_settings_submit').click(function(ev){
  	saveSubject();
  });
  
});