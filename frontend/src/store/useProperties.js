import {useState} from 'react';
import {initialProperties} from '../data/properties';
const KEY='trofelli-demo-v1';
export function useProperties(){
 const [items,setItems]=useState(()=>{try{const p=JSON.parse(localStorage.getItem(KEY));return Array.isArray(p)?p:initialProperties}catch{return initialProperties}});
 const save=(next)=>{localStorage.setItem(KEY,JSON.stringify(next));setItems(next)};
 return {items,save};
}
