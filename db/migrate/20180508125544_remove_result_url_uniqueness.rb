class RemoveResultUrlUniqueness < ActiveRecord::Migration
    def change
        remove_index :results, name: 'unique_results'
        add_index :results, :url, name: 'index_results'
    end
end
