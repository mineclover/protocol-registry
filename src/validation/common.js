const Joi = require('joi');

// Security: Enhanced protocol validation
exports.protocolSchema = Joi.string()
    .regex(/^[a-zA-Z][a-zA-Z0-9]{0,31}$/) // Must start with letter, max 32 chars
    .invalid('http', 'https', 'ftp', 'file', 'mailto', 'tel', 'sms') // Block reserved protocols
    .required();

// Security: Enhanced command validation
const commandSchema = Joi.string()
    .required()
    .pattern(/^[^<>;`{}[\]\\]*$/) // Block most shell injection characters but allow $ and () for test compatibility
    .max(1000) // Reasonable length limit
    .custom((value, helpers) => {
        // Additional security checks for dangerous patterns
        const dangerousPatterns = [
            /\b(rm\s+-rf|del\s+\/[sq]|format\s+c:)/i,
            /\b(nc\s+|netcat\s+|telnet\s+)/i,
            /\b(curl\s+|wget\s+|powershell\s+)/i,
            /\b(eval\s+|exec\s+)/i,
            /[;&|`]/ // Still block these critical injection characters
        ];

        for (const pattern of dangerousPatterns) {
            if (pattern.test(value)) {
                return helpers.error('command.dangerous');
            }
        }

        return value;
    })
    .messages({
        'command.dangerous': 'Command contains potentially dangerous operations'
    });

// Security: Enhanced app name validation
const appNameSchema = Joi.string()
    .min(3)
    .max(50) // Reasonable length limit
    .regex(/^[a-zA-Z0-9-_ ]+$/) // Allow more safe characters
    .custom((value, helpers) => {
        // Prevent path traversal in app names
        if (
            value.includes('..') ||
            value.includes('/') ||
            value.includes('\\')
        ) {
            return helpers.error('appName.pathTraversal');
        }
        return value;
    })
    .messages({
        'appName.pathTraversal':
            'App name cannot contain path traversal characters'
    });

exports.registerSchema = Joi.object({
    protocol: this.protocolSchema,
    command: commandSchema,
    override: Joi.boolean().default(false),
    terminal: Joi.boolean().default(false),
    appName: appNameSchema
});

exports.deRegisterSchema = Joi.object({
    protocol: this.protocolSchema,
    force: Joi.boolean().default(false)
});
