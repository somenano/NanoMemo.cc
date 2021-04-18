function dateClassToLocal() {
    $('.date-to-local').each(function() {
        const date_string = new Date($(this).text()).toLocaleString();
        $(this).text(date_string);
    });
}
$( document ).ready(function() {
    dateClassToLocal();
});