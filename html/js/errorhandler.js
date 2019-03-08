window.onerror = function(errorMsg, url, lineNumber) {
    alert(errorMsg + ' Script: ' + url + ' Line: ' + lineNumber);
    try {
        $("body").loader("hide");
        document.title = "Maltrail";
    }
    catch(err) {
    }
};

