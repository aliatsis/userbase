var schema = require('validate');

var messageAdaptorSchema = schema({
    sendResetPasswordLink: {
        type: 'function',
        required: true,
        message: 'messageAdaptor \'sendResetPasswordLink\' function is required'
    },
    sendResetPasswordConfirmation: {
        type: 'function',
        message: 'messageAdaptor \'sendResetPasswordConfirmation\' function is required'
    },
    sendSignupConfirmation: {
        type: 'function',
        message: 'messageAdaptor \'sendSignupConfirmation\' function is required'
    }
});

module.exports = function(adaptor) {
    var errors = messageAdaptorSchema.validate(adaptor, {
        strip: false
    });
};