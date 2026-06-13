module.exports = {
    upgrade: true,
    reject: ['eslint-config-prettier', 'express'],
    // do not update joi from 17, check emailengine joi compatibility first
    target: (name) => (name === 'joi' ? 'minor' : 'latest')
};
