window.onerror = function(errorMsg, url, lineNumber) {
    if (typeof errorMsg !== "undefined")
        alert(errorMsg + ' Script: ' + url + ' Line: ' + lineNumber);

    try {
        $("body").loader("hide");
        document.title = "Maltrail";
    }
    catch(err) {
    }
};

