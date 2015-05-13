var Promise = require("es6-promise").Promise;

module.exports = function(promise, errorDescription) {
    // if (promise instanceof Promise) {
    if (typeof promise.then === 'function') {
        return promise;
    } else {
        var errorMsg;

        if (errorDescription) {
            errorMsg = errorDescription + ' must return a thenable Promise';
        } else {
            errorMsg = 'Expected a thenable Promise but received ' + promise;
        }

        throw new Error(errorMsg);
    }
};