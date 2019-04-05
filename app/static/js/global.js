function del(target_id) {
    message = confirm("是否删除?");
    if(message==true){
        $.ajax({
            url:'/targets/'+target_id,
            type:'DELETE',
            success:function (result) {
                alert(result);
            }

        })
    }else{
        return false
    }
}


function recheckvuln(vuln_id){
    if(confirm("重新测试?")){
        $.ajax({
            url:'/vulnerabilities/'+vuln_id,
            type:'PUT',
            success:function (result) {
                alert(result)
            }
        })
    }else{
        return
    }
}

function del_scan(scan_id) {
    message = confirm("是否删除?");
    if(message==true){
        $.ajax({
            url:'/scans/'+scan_id,
            type:'DELETE',
            success:function (result) {
                alert(result);

            }

        })
    }else{
        return false
    }
}


function generate(scan_id) {
    message = confirm("是否生成报告?");
    if(message==true){
        $.ajax({
            url:'/report/'+scan_id,
            type:'GET',
            success:function (result) {
                alert(result);

            }

        })
    }else{
        return false
    }



}
$(function () { $("[data-toggle='tooltip']").tooltip(); });