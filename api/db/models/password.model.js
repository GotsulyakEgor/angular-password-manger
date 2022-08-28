const mongoose = require('mongoose')

const PasswordSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        minLength: 1,
        trim: true
    },
    _listId: {
        type: mongoose.Types.ObjectId,
        required: true
    }
})

const Password = mongoose.model('Password', PasswordSchema);

module.exports = { Password }