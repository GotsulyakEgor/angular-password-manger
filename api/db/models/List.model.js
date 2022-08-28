const mongoose = require('mongoose')

const ListSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        minLength: 1,
        trim: true
    },
    titleAccount: {
        type: String,
        required: false,
        minLength: 0,
        trim: true
    },

    password: {
        type: String,
        required: true,
        minLength: 1,
        trim: true
    },
    _userId: {
        type: mongoose.Types.ObjectId,
        required: true,
    },
    togglePassword: {
        type: Boolean,
        required: true,
        minLength: 1,
        trim: true
    },
})

const List = mongoose.model("List", ListSchema);

module.exports = { List }