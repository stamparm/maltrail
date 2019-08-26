window.onerror = function(errorMsg, url, lineNumber) {
    if (typeof errorMsg !== "string") {
        if (errorMsg.hasOwnProperty("filename"))
            url = errorMsg.filename;

        if (errorMsg.hasOwnProperty("lineno"))
            lineNumber = errorMsg.lineno;

        if (errorMsg.hasOwnProperty("message"))
            errorMsg = errorMsg.message;
    }

    alert(errorMsg + ' Script: ' + url + ' Line: ' + lineNumber);

    try {
        $("body").loader("hide");
        document.title = "Maltrail";
    }
    catch(err) {
    }
};

