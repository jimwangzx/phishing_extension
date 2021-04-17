var baseNode = Object.defineProperties({},
   {
      //Campi del nodo
      chars: {writable: true, value: null},
      end : {writable: true, value: null}
   });

function Node(){
   this.chars = new Map();
   this.end = false;
}

Node.prototype = baseNode;

//Struttura Trie
var baseTrie = Object.defineProperties({},
   {
      //Campi del Trie
      root: {writable: true, value: null},

      //Metodi del Trie
      insert: {writable: false, value: function(word){
         if (typeof word === 'undefined') return null;

         var current = this.root;

         for (let c of word){
            if (!current.chars.has(c)){
               current.chars.set(c, new Node());
            }
            current = current.chars.get(c);
         }
         current.end = true;
      }},
      search: {writable: false, value: function(word){
         if (typeof word === 'undefined') return false;

         var current = this.root;

         for (let c of word){
            if (!current.chars.has(c)){
               return false;
            }
            current = current.chars.get(c);
         }
         return current.end;
      }},
      remove: {writable: false, value: function(word){

      }}

   });

function Trie(){
   this.root = new Node();
}

Trie.prototype = baseTrie;
